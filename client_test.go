package transport

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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

	client := NewClient(10, 0, 3, 10)

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

func TestRateLimiting(t *testing.T) {
	requestTimes := []time.Time{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := NewClient(10, 2, 0, 10)

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		client.Do(req, 2)
	}

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

func TestCircuitBreaker(t *testing.T) {
	client := NewClient(10, 0, 1, 10)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	for i := 0; i < 15; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		client.Do(req, 0)
	}

	if !client.circuitBreaker.isOpen(server.URL) {
		t.Error("expected circuit breaker to be open")
	}

	req, _ := http.NewRequest("GET", server.URL, nil)
	_, _, err := client.Do(req, 0)

	if err == nil {
		t.Error("expected circuit breaker error")
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

	client := NewClient(10, 0, 0, 1)

	req, _ := http.NewRequest("GET", server.URL, nil)
	_, body, err := client.Do(req, 0)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(body) > 1*1024*1024 {
		t.Errorf("body size exceeded limit: %d bytes", len(body))
	}
}