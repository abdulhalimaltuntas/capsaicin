package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"golang.org/x/time/rate"
)

// Client is the highly customized transport manager for Capasicin v2.
type Client struct {
	httpClient     *http.Client
	config         *config.Config
	limiters       map[string]*rate.Limiter
	limitersMu     sync.RWMutex
	maxBodyBytes   int64
	circuitBreaker *CircuitBreaker

	// Evasion state (per-worker instantiation is optimal, but shared is OK if locked)
	tlsProfile    string
	headerProfile *BrowserProfile
	jitterEngine  *JitterEngine

	rng   *rand.Rand
	rngMu sync.Mutex

	// proxyPool rotates outbound proxies; nil when no --proxy/--proxy-file set.
	proxyPool *proxyPool

	// closeFn releases transport-owned resources (e.g. the HTTP/3 QUIC pool).
	closeFn func() error
}

// CircuitBreaker guards against 5xx storms and connection resets.
type CircuitBreaker struct {
	mu            sync.Mutex
	failureCounts map[string]int
	lastFailure   map[string]time.Time
	threshold     int
	resetTimeout  time.Duration
}

// NewClient constructs an http.Client built specifically for bypassing advanced WAFs.
func NewClient(cfg *config.Config) (*Client, error) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Proxy pool (single --proxy or --proxy-file with a rotation strategy).
	pool, err := newProxyPool(cfg.Proxy, cfg.ProxyFile, cfg.ProxyStrategy, rng)
	if err != nil {
		return nil, err
	}
	proxyFunc := pool.proxyFunc()

	// Shared TCP dialer, wired to custom --resolvers when provided.
	dialer := newDialer(cfg.Resolvers, 5*time.Second)

	var tp http.RoundTripper
	var closeFn func() error

	tlsImpersonate := cfg.TLSImpersonate
	if tlsImpersonate == "" {
		tlsImpersonate = "none"
	}

	// Determine Transport Type. HTTP/3 (QUIC) takes precedence when requested,
	// otherwise HTTP/2 with uTLS spoofing, otherwise the standard HTTP/1.1 path.
	if cfg.EnableHTTP3 {
		h3Builder := NewH3TransportBuilder()
		h3Builder.HandshakeTimeout = time.Duration(cfg.Timeout) * time.Second
		h3Builder.ServerName = cfg.SNI
		rt, closer, err := h3Builder.Build()
		if err != nil {
			return nil, err
		}
		tp = rt
		closeFn = closer
	} else if cfg.ForceHTTP2 {
		// uTLS JA3/JA4 impersonation. The h2 transport only speaks HTTP/2 over
		// TLS, so it is paired with a uTLS HTTP/1.1 transport (same spoofed
		// ClientHello) and a scheme/ALPN dispatcher — otherwise http:// targets
		// and HTTP/1.1-only HTTPS targets would error on every request.
		helloID := GetTLSProfile(tlsImpersonate, rng)
		dialTimeout := time.Duration(cfg.Timeout) * time.Second

		h2Builder := NewH2TransportBuilder()
		h2Builder.HelloID = helloID
		h2Builder.DialTimeout = dialTimeout
		h2Builder.ProxyFunc = proxyFunc // Note: h2 + SOCKS proxy needs standard dialer proxy support
		h2Builder.Dialer = dialer
		h2Builder.SNI = cfg.SNI

		t2, err := h2Builder.Build()
		if err != nil {
			return nil, err
		}
		tp = &dispatchTransport{
			h2: t2,
			h1: newUTLSH1Transport(helloID, proxyFunc, dialer, cfg.SNI),
		}
	} else {
		// Default transport: standard HTTP/1.1 that transparently upgrades to
		// HTTP/2 over TLS via ALPN (with automatic HTTP/1.1 fallback) and speaks
		// cleartext http:// correctly. This is the robust default; uTLS
		// fingerprint spoofing is opt-in via --h2.
		tp = &http.Transport{
			Proxy:                 proxyFunc,
			MaxIdleConns:          500,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: time.Duration(cfg.Timeout) * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext:           dialer.DialContext,
			// Scanners routinely hit self-signed/expired/hostname-mismatched
			// certs; skip verification to match the uTLS paths. SNI is
			// overridden only when --sni is set (else per-host default).
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         cfg.SNI,
			},
			ForceAttemptHTTP2: true,
		}
	}

	httpClient := &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: tp,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow automatically // Don't follow automatically
		},
	}

	var headerProfile *BrowserProfile
	if cfg.HeaderRotation || tlsImpersonate != "none" {
		headerProfile = GetCoherentProfile(tlsImpersonate, rng)
	}

	jitterEngine := NewJitterEngine(cfg.JitterProfile, rng)

	// A zero/negative body cap would make io.LimitReader truncate every
	// response to zero bytes — silently breaking secret detection, soft-404
	// body matching, and fingerprinting. Fall back to a sane default so a
	// Config literal that skips validation (e.g. the cluster agent) still works.
	maxBodyBytes := int64(cfg.MaxResponseMB) * 1024 * 1024
	if maxBodyBytes <= 0 {
		maxBodyBytes = 10 * 1024 * 1024
	}

	cbThreshold := cfg.CBThreshold
	if cbThreshold <= 0 {
		cbThreshold = 20
	}
	cbReset := time.Duration(cfg.CBResetSeconds) * time.Second
	if cbReset <= 0 {
		cbReset = 30 * time.Second
	}

	return &Client{
		httpClient:   httpClient,
		config:       cfg,
		limiters:     make(map[string]*rate.Limiter),
		maxBodyBytes: maxBodyBytes,
		circuitBreaker: &CircuitBreaker{
			failureCounts: make(map[string]int),
			lastFailure:   make(map[string]time.Time),
			threshold:     cbThreshold,
			resetTimeout:  cbReset,
		},
		tlsProfile:    tlsImpersonate,
		headerProfile: headerProfile,
		jitterEngine:  jitterEngine,
		rng:           rng,
		proxyPool:     pool,
		closeFn:       closeFn,
	}, nil
}

// Close releases transport-owned resources. Safe to call on any Client.
func (c *Client) Close() error {
	if c.closeFn != nil {
		return c.closeFn()
	}
	return nil
}

func (c *Client) getRateLimiter(host string, rateLimit int) *rate.Limiter {
	if rateLimit <= 0 {
		return nil
	}
	c.limitersMu.RLock()
	limiter, exists := c.limiters[host]
	c.limitersMu.RUnlock()
	if exists {
		return limiter
	}
	c.limitersMu.Lock()
	defer c.limitersMu.Unlock()
	if limiter, exists := c.limiters[host]; exists {
		return limiter
	}
	limiter = rate.NewLimiter(rate.Limit(rateLimit), 1)
	c.limiters[host] = limiter
	return limiter
}

// retryBackoff is orthogonal to the stochastic jitter engine. Jitter is *inter-request*
// stealth delay. retryBackoff is *failure recovery* delay.
func (c *Client) retryBackoff(attempt int) time.Duration {
	ceiling := 15 * time.Second
	base := time.Duration(math.Pow(2, float64(attempt))) * time.Second
	if base > ceiling {
		base = ceiling
	}
	c.rngMu.Lock()
	d := time.Duration(c.rng.Int63n(int64(base)))
	c.rngMu.Unlock()
	return d
}

// Do executes an HTTP request, handling rate limiting, jitter, retries, and circuit breaking.
func (c *Client) Do(req *http.Request, rateLimit int) (*http.Response, []byte, error) {
	return c.DoContext(req.Context(), req, rateLimit)
}

// DoContext is the context-aware execution pipeline.
func (c *Client) DoContext(ctx context.Context, req *http.Request, rateLimit int) (*http.Response, []byte, error) {
	parsedURL, err := url.Parse(req.URL.String())
	if err != nil {
		return nil, nil, err
	}
	host := parsedURL.Host

	if c.circuitBreaker.isOpen(host) {
		return nil, nil, fmt.Errorf("circuit breaker open for host: %s", host)
	}

	// 1. Rate Limiting (absolute ceiling per host)
	limiter := c.getRateLimiter(host, rateLimit)
	if limiter != nil {
		if err := limiter.Wait(ctx); err != nil {
			return nil, nil, fmt.Errorf("rate limiter cancelled: %w", err)
		}
	}

	// 2. Stochastic Jitter (evasion logic, simulates human pacing)
	if c.config.JitterProfile != "" {
		c.rngMu.Lock()
		delay := c.jitterEngine.NextDelay()
		c.rngMu.Unlock()

		if delay > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	// 3. Coherent Header Injection
	if c.headerProfile != nil {
		ApplyProfile(req, c.headerProfile)
	}

	req = req.WithContext(ctx)

	var resp *http.Response
	var body []byte

	// 4. Execution Loop (with Retries)
	for attempt := 0; attempt <= c.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			backoff := c.retryBackoff(attempt - 1)
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		resp, err = c.httpClient.Do(req)
		if err != nil {
			c.proxyPool.markFailed() // failover strategy: rotate off a bad proxy
			if attempt == c.config.RetryAttempts {
				c.circuitBreaker.recordFailure(host)
				return nil, nil, err
			}
			continue
		}

		body, err = c.readBody(resp.Body)
		resp.Body.Close()

		if err != nil {
			if attempt == c.config.RetryAttempts {
				c.circuitBreaker.recordFailure(host)
				return nil, nil, err
			}
			continue
		}

		// 5xx logic - counts towards circuit breaker but might still return to caller
		if resp.StatusCode >= 500 {
			c.circuitBreaker.recordFailure(host)
			if attempt == c.config.RetryAttempts {
				return resp, body, nil
			}
			continue
		}

		c.circuitBreaker.recordSuccess(host)
		return resp, body, nil
	}

	return nil, nil, fmt.Errorf("request failed after %d attempts", c.config.RetryAttempts+1)
}

func (c *Client) readBody(body io.ReadCloser) ([]byte, error) {
	limitedReader := io.LimitReader(body, c.maxBodyBytes)
	return io.ReadAll(limitedReader)
}

func (cb *CircuitBreaker) isOpen(host string) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if lastFail, exists := cb.lastFailure[host]; exists {
		if time.Since(lastFail) > cb.resetTimeout {
			delete(cb.failureCounts, host)
			delete(cb.lastFailure, host)
			return false
		}
	}
	return cb.failureCounts[host] >= cb.threshold
}

func (cb *CircuitBreaker) recordFailure(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failureCounts[host]++
	cb.lastFailure[host] = time.Now()
}

func (cb *CircuitBreaker) recordSuccess(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	delete(cb.failureCounts, host)
	delete(cb.lastFailure, host)
}

func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
