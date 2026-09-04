package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/capsaicin/scanner/internal/config"
)

func TestClientRetry(t *testing.T) {
	attempts := int32(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 3, MaxResponseMB: 10})

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, body, err := client.Do(req, 0)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if string(body) != "success" {
		t.Errorf("unexpected body: %s", body)
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestClientRetry_AllFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, body, err := client.Do(req, 0)

	if err != nil {
		t.Fatalf("expected no error (5xx returns response), got %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}

	_ = body
}

func TestRateLimiting(t *testing.T) {
	requestTimes := []time.Time{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		client.Do(req, 2)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(requestTimes) < 5 {
		t.Fatalf("expected 5 requests, got %d", len(requestTimes))
	}

	for i := 1; i < len(requestTimes); i++ {
		diff := requestTimes[i].Sub(requestTimes[i-1])
		if diff < 400*time.Millisecond {
			t.Errorf("requests too close together: %v", diff)
		}
	}
}

func TestRateLimiting_Disabled(t *testing.T) {
	requestCount := int32(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	start := time.Now()
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		client.Do(req, 0)
	}
	elapsed := time.Since(start)

	if atomic.LoadInt32(&requestCount) != 10 {
		t.Errorf("expected 10 requests, got %d", requestCount)
	}

	if elapsed > 2*time.Second {
		t.Errorf("unlimited rate limiter should be fast, took %v", elapsed)
	}
}

func TestCircuitBreaker(t *testing.T) {
	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	for i := 0; i < 25; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		client.Do(req, 0)
	}

	parsedURL, _ := url.Parse(server.URL)
	if !client.circuitBreaker.isOpen(parsedURL.Host) {
		t.Error("expected circuit breaker to be open")
	}

	req, _ := http.NewRequest("GET", server.URL, nil)
	_, _, err := client.Do(req, 0)

	if err == nil {
		t.Error("expected circuit breaker error")
	}
}

func TestCircuitBreakerRecoversAfterSuccessfulRequest(t *testing.T) {
	attempts := int32(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count <= 20 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		client.Do(req, 0)
	}

	parsedURL, _ := url.Parse(server.URL)
	if !client.circuitBreaker.isOpen(parsedURL.Host) {
		t.Fatal("expected circuit breaker to be open after consecutive failures")
	}

	client.circuitBreaker.lastFailure[parsedURL.Host] = time.Now().Add(-31 * time.Second)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, _, err := client.Do(req, 0)
	if err != nil {
		t.Fatalf("expected request after cooldown to succeed, got error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status code 200 after recovery, got %d", resp.StatusCode)
	}

	if client.circuitBreaker.isOpen(parsedURL.Host) {
		t.Fatal("expected circuit breaker to close after successful request")
	}
}

func TestMaxBodySize(t *testing.T) {
	largeBody := make([]byte, 5*1024*1024)
	for i := range largeBody {
		largeBody[i] = 'A'
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(largeBody)
	}))
	defer server.Close()

	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 1})

	req, _ := http.NewRequest("GET", server.URL, nil)
	_, body, err := client.Do(req, 0)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(body) > 1*1024*1024 {
		t.Errorf("body size exceeded limit: %d bytes", len(body))
	}
}

func TestCircuitBreaker_IsOpen_Reset(t *testing.T) {
	cb := &CircuitBreaker{
		failureCounts: make(map[string]int),
		lastFailure:   make(map[string]time.Time),
		threshold:     5,
		resetTimeout:  1 * time.Second,
	}

	host := "example.com"

	for i := 0; i < 5; i++ {
		cb.recordFailure(host)
	}

	if !cb.isOpen(host) {
		t.Error("expected circuit breaker to be open")
	}

	cb.lastFailure[host] = time.Now().Add(-2 * time.Second)

	if cb.isOpen(host) {
		t.Error("expected circuit breaker to be closed after reset timeout")
	}

	if cb.failureCounts[host] != 0 {
		t.Errorf("expected failure count to be reset, got %d", cb.failureCounts[host])
	}
}

func TestCircuitBreaker_RecordSuccess_ClearsFailures(t *testing.T) {
	cb := &CircuitBreaker{
		failureCounts: make(map[string]int),
		lastFailure:   make(map[string]time.Time),
		threshold:     10,
		resetTimeout:  30 * time.Second,
	}

	host := "example.com"

	for i := 0; i < 5; i++ {
		cb.recordFailure(host)
	}

	if cb.failureCounts[host] != 5 {
		t.Errorf("expected 5 failures, got %d", cb.failureCounts[host])
	}

	cb.recordSuccess(host)

	if cb.failureCounts[host] != 0 {
		t.Errorf("expected 0 failures after success, got %d", cb.failureCounts[host])
	}

	if _, exists := cb.lastFailure[host]; exists {
		t.Error("expected lastFailure to be cleared after success")
	}
}

func TestClient_HTTPClient(t *testing.T) {
	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})
	httpClient := client.HTTPClient()

	if httpClient == nil {
		t.Error("expected non-nil http client")
	}

	if httpClient.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", httpClient.Timeout)
	}
}

func TestClient_RedirectPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/destination", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("destination"))
	}))
	defer server.Close()

	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	req, _ := http.NewRequest("GET", server.URL+"/redirect", nil)
	resp, _, err := client.Do(req, 0)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 301 {
		t.Errorf("expected 301 (no follow), got %d", resp.StatusCode)
	}
}

func TestRateLimiter_MultipleHosts(t *testing.T) {
	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	limiter1 := client.getRateLimiter("host1.com", 5)
	limiter2 := client.getRateLimiter("host2.com", 5)

	if limiter1 == limiter2 {
		t.Error("expected different limiters for different hosts")
	}

	limiter1Again := client.getRateLimiter("host1.com", 5)
	if limiter1 != limiter1Again {
		t.Error("expected same limiter for same host")
	}
}

func TestRateLimiter_Concurrent(t *testing.T) {
	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.getRateLimiter("concurrent-host.com", 10)
		}()
	}
	wg.Wait()

	client.limitersMu.RLock()
	count := len(client.limiters)
	client.limitersMu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 limiter for the host, got %d", count)
	}
}

func TestClient_ConnectionRefused(t *testing.T) {
	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	req, _ := http.NewRequest("GET", "http://127.0.0.1:1", nil)
	_, _, err := client.Do(req, 0)

	if err == nil {
		t.Error("expected error for connection refused")
	}
}

func TestClient_InvalidURL(t *testing.T) {
	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	req, err := http.NewRequest("GET", "://invalid", nil)
	if err != nil {
		return
	}

	_, _, err = client.Do(req, 0)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestCircuitBreaker_Concurrent(t *testing.T) {
	cb := &CircuitBreaker{
		failureCounts: make(map[string]int),
		lastFailure:   make(map[string]time.Time),
		threshold:     100,
		resetTimeout:  30 * time.Second,
	}

	var wg sync.WaitGroup
	host := "concurrent.example.com"

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%3 == 0 {
				cb.recordFailure(host)
			} else if idx%3 == 1 {
				cb.recordSuccess(host)
			} else {
				cb.isOpen(host)
			}
		}(i)
	}
	wg.Wait()

	_ = context.Background()
}
