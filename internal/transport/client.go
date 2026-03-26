package transport

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
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
	tlsProfile     string
	headerProfile  *BrowserProfile
	jitterEngine   *JitterEngine
	
	rng *rand.Rand
	rngMu sync.Mutex
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
	
	// Parse proxy if provided
	var proxyFunc func(*http.Request) (*url.URL, error)
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		proxyFunc = http.ProxyURL(proxyURL)
	} else {
		proxyFunc = http.ProxyFromEnvironment
	}

	var tp http.RoundTripper

	tlsImpersonate := cfg.TLSImpersonate
	if tlsImpersonate == "" {
		tlsImpersonate = "none"
	}

	// Determine Transport Type (HTTP/2 vs Standard)
	if cfg.ForceHTTP2 {
		helloID := GetTLSProfile(tlsImpersonate, rng)
		
		h2Builder := NewH2TransportBuilder()
		h2Builder.HelloID = helloID
		h2Builder.DialTimeout = time.Duration(cfg.Timeout) * time.Second
		h2Builder.ProxyFunc = proxyFunc // Note: h2 + SOCKS proxy needs standard dialer proxy support
		
		t2, err := h2Builder.Build()
		if err != nil {
			return nil, err
		}
		tp = t2
	} else {
		// Fallback standard transport (HTTP/1.1) but still with customized settings
		tp = &http.Transport{
			Proxy:                 proxyFunc,
			MaxIdleConns:          500,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: time.Duration(cfg.Timeout) * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     false,
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

	return &Client{
		httpClient:     httpClient,
		config:         cfg,
		limiters:       make(map[string]*rate.Limiter),
		maxBodyBytes:   int64(cfg.MaxResponseMB) * 1024 * 1024,
		circuitBreaker: &CircuitBreaker{
			failureCounts: make(map[string]int),
			lastFailure:   make(map[string]time.Time),
			threshold:     20, // slightly higher threshold for fuzzer
			resetTimeout:  30 * time.Second,
		},
		tlsProfile:     tlsImpersonate,
		headerProfile:  headerProfile,
		jitterEngine:   jitterEngine,
		rng:            rng,
	}, nil
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
