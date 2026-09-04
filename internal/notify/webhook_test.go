package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/abdulhalimaltuntas/capsaicin/internal/scanner"
)

func TestSendWebhook(t *testing.T) {
	var mu sync.Mutex
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		mu.Lock()
		got = string(b)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	results := []scanner.Result{
		{URL: "http://x/a", StatusCode: 200, Severity: "critical", SecretFound: true, SecretTypes: []string{"AWS"}},
		{URL: "http://x/b", StatusCode: 200, Severity: "low"}, // below threshold
	}
	n, err := SendWebhook(context.Background(), srv.URL, results, "high")
	if err != nil {
		t.Fatalf("SendWebhook: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 finding >= high, got %d", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(got, "http://x/a") || !strings.Contains(got, "AWS") {
		t.Errorf("payload missing finding detail: %s", got)
	}
}

func TestSendWebhook_NoHits(t *testing.T) {
	n, err := SendWebhook(context.Background(), "http://unused", []scanner.Result{{Severity: "low"}}, "critical")
	if err != nil || n != 0 {
		t.Errorf("expected no-op when nothing meets threshold, got n=%d err=%v", n, err)
	}
}
