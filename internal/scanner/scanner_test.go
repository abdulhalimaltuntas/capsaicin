package scanner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/capsaicin/scanner/internal/config"
)

func TestEngineBasicScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			w.Write([]byte("Admin panel"))
		} else if r.URL.Path == "/secret" {
			w.WriteHeader(200)
			w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())

	wordlist.WriteString("admin\nsecret\nnotfound\n")
	wordlist.Close()

	cfg := config.Config{
		Wordlist:      wordlist.Name(),
		Threads:       2,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
	}

	engine := NewEngine(cfg)
	results, stats, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	if stats.GetFound() != 2 {
		t.Errorf("expected 2 found, got %d", stats.GetFound())
	}

	if stats.GetSecrets() != 1 {
		t.Errorf("expected 1 secret, got %d", stats.GetSecrets())
	}

	foundSecret := false
	for _, r := range results {
		if r.SecretFound {
			foundSecret = true
		}
	}

	if !foundSecret {
		t.Error("expected to find secret")
	}
}

func TestEngineRecursiveScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" {
			w.Header().Set("Location", r.URL.Path+"/")
			w.WriteHeader(301)
		} else if r.URL.Path == "/api/" {
			w.WriteHeader(200)
		} else if r.URL.Path == "/api/users" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())

	wordlist.WriteString("api\nusers\n")
	wordlist.Close()

	cfg := config.Config{
		Wordlist:      wordlist.Name(),
		Threads:       2,
		Timeout:       10,
		MaxDepth:      2,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
	}

	engine := NewEngine(cfg)
	results, stats, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(results) < 2 {
		t.Errorf("expected at least 2 results, got %d", len(results))
	}

	if stats.GetFound() < 2 {
		t.Errorf("expected at least 2 found, got %d", stats.GetFound())
	}
}

func TestEngineWAFDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(200)
	}))
	defer server.Close()

	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())

	wordlist.WriteString("test\n")
	wordlist.Close()

	cfg := config.Config{
		Wordlist:      wordlist.Name(),
		Threads:       1,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
	}

	engine := NewEngine(cfg)
	results, stats, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if stats.GetWAFHits() != 1 {
		t.Errorf("expected 1 WAF hit, got %d", stats.GetWAFHits())
	}

	if len(results) > 0 && results[0].WAFDetected != "Cloudflare" {
		t.Errorf("expected Cloudflare WAF, got %s", results[0].WAFDetected)
	}
}

func TestStatsAccuracy(t *testing.T) {
	stats := NewStats(100)

	stats.IncrementProcessed()
	stats.IncrementProcessed()
	stats.IncrementFound()
	stats.IncrementSecrets()
	stats.IncrementWAFHits()
	stats.IncrementErrors()

	if stats.GetProcessed() != 2 {
		t.Errorf("expected processed=2, got %d", stats.GetProcessed())
	}

	if stats.GetFound() != 1 {
		t.Errorf("expected found=1, got %d", stats.GetFound())
	}

	if stats.GetSecrets() != 1 {
		t.Errorf("expected secrets=1, got %d", stats.GetSecrets())
	}

	if stats.GetWAFHits() != 1 {
		t.Errorf("expected waf=1, got %d", stats.GetWAFHits())
	}

	if stats.GetErrors() != 1 {
		t.Errorf("expected errors=1, got %d", stats.GetErrors())
	}
}