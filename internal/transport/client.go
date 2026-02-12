package transport

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type Client struct {
	httpClient     *http.Client
	limiters       map[string]*rate.Limiter
	limitersMu     sync.RWMutex
	retryAttempts  int
	maxBodyBytes   int64
	circuitBreaker *CircuitBreaker
}

type CircuitBreaker struct {
	mu            sync.Mutex
	failureCounts map[string]int
	lastFailure   map[string]time.Time
	threshold     int
	resetTimeout  time.Duration
}

func NewClient(timeout int, rateLimit int, retryAttempts int, maxBodyMB int) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		limiters:      make(map[string]*rate.Limiter),
		retryAttempts: retryAttempts,
		maxBodyBytes:  int64(maxBodyMB) * 1024 * 1024,
		circuitBreaker: &CircuitBreaker{
			failureCounts: make(map[string]int),
			lastFailure:   make(map[string]time.Time),
			threshold:     10,
			resetTimeout:  30 * time.Second,
		},
	}
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

func (c *Client) Do(req *http.Request, rateLimit int) (*http.Response, []byte, error) {
	parsedURL, err := url.Parse(req.URL.String())
	if err != nil {
		return nil, nil, err
	}

	host := parsedURL.Host

	if c.circuitBreaker.isOpen(host) {
		return nil, nil, fmt.Errorf("circuit breaker open for host: %s", host)
	}

	limiter := c.getRateLimiter(host, rateLimit)
	if limiter != nil {
		if err := limiter.Wait(context.Background()); err != nil {
			return nil, nil, err
		}
	}

	var resp *http.Response
	var body []byte

	for attempt := 0; attempt <= c.retryAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			jitter := time.Duration(rand.Int63n(int64(backoff) / 2))
			time.Sleep(backoff + jitter)
		}

		resp, err = c.httpClient.Do(req)
		if err != nil {
			if attempt == c.retryAttempts {
				c.circuitBreaker.recordFailure(host)
				return nil, nil, err
			}
			continue
		}

		body, err = c.readBody(resp.Body)
		resp.Body.Close()

		if err != nil {
			if attempt == c.retryAttempts {
				c.circuitBreaker.recordFailure(host)
				return nil, nil, err
			}
			continue
		}

		if resp.StatusCode >= 500 {
			c.circuitBreaker.recordFailure(host)
			if attempt == c.retryAttempts {
				return resp, body, nil
			}
			continue
		}

		c.circuitBreaker.recordSuccess(host)
		return resp, body, nil
	}

	return nil, nil, fmt.Errorf("request failed after %d attempts", c.retryAttempts+1)
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

	count := cb.failureCounts[host]
	return count >= cb.threshold
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

	if count := cb.failureCounts[host]; count > 0 {
		cb.failureCounts[host] = count - 1
	}
}

func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
