package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/capsaicin/scanner/internal/config"
)

func BenchmarkClientDo_Success(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		client.Do(req, 0)
	}
}

func BenchmarkRateLimiter_GetOrCreate(b *testing.B) {
	client, _ := NewClient(&config.Config{Timeout: 10, RetryAttempts: 0, MaxResponseMB: 10})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.getRateLimiter("bench-host.com", 10)
	}
}

func BenchmarkCircuitBreaker_IsOpen(b *testing.B) {
	cb := &CircuitBreaker{
		failureCounts: make(map[string]int),
		lastFailure:   make(map[string]time.Time),
		threshold:     10,
		resetTimeout:  30 * time.Second,
	}
	host := "bench-host.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.isOpen(host)
	}
}
