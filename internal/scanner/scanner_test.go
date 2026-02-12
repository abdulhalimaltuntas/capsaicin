package scanner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/capsaicin/scanner/internal/config"
)

func createWordlist(t *testing.T, words ...string) string {
	t.Helper()
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(wordlist.Name()) })
	wordlist.WriteString(strings.Join(words, "\n") + "\n")
	wordlist.Close()
	return wordlist.Name()
}

func TestEngineBasicScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			w.Write([]byte("Admin panel"))
		} else if r.URL.Path == "/secret" {
			w.WriteHeader(200)
			w.Write([]byte("AK" + "IA" + "IOSFODNN7" + "SCANTEST1"))
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	wordlistPath := createWordlist(t, "admin", "secret", "notfound")

	cfg := config.Config{
		Wordlist:      wordlistPath,
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

	wordlistPath := createWordlist(t, "api", "users")

	cfg := config.Config{
		Wordlist:      wordlistPath,
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

	wordlistPath := createWordlist(t, "test")

	cfg := config.Config{
		Wordlist:      wordlistPath,
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

func TestStatsIncrementTotal(t *testing.T) {
	stats := NewStats(10)
	stats.IncrementTotal(5)

	if stats.GetTotal() != 15 {
		t.Errorf("expected total=15, got %d", stats.GetTotal())
	}
}

func TestStatsConcurrent(t *testing.T) {
	stats := NewStats(0)
	done := make(chan struct{})

	for i := 0; i < 100; i++ {
		go func() {
			stats.IncrementProcessed()
			stats.IncrementFound()
			stats.IncrementErrors()
			stats.IncrementSecrets()
			stats.IncrementWAFHits()
			stats.IncrementTotal(1)
			<-done
		}()
	}

	close(done)
	time.Sleep(50 * time.Millisecond)

	if stats.GetProcessed() != 100 {
		t.Errorf("expected processed=100, got %d", stats.GetProcessed())
	}
}

func TestIsInteresting(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{"200 OK", 200, true},
		{"201 Created", 201, true},
		{"301 Redirect", 301, true},
		{"302 Found", 302, true},
		{"399 Edge", 399, true},
		{"401 Unauthorized", 401, true},
		{"403 Forbidden", 403, true},
		{"404 Not Found", 404, false},
		{"500 Server Error", 500, false},
		{"100 Continue", 100, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &Result{StatusCode: tt.statusCode}
			got := isInteresting(result)
			if got != tt.expected {
				t.Errorf("isInteresting(%d) = %v, expected %v", tt.statusCode, got, tt.expected)
			}
		})
	}
}

func TestIsDirectory(t *testing.T) {
	tests := []struct {
		name     string
		result   *Result
		expected bool
	}{
		{"301 redirect", &Result{StatusCode: 301, URL: "http://a.com/dir"}, true},
		{"302 redirect", &Result{StatusCode: 302, URL: "http://a.com/dir"}, true},
		{"403 forbidden", &Result{StatusCode: 403, URL: "http://a.com/dir"}, true},
		{"trailing slash", &Result{StatusCode: 200, URL: "http://a.com/dir/"}, true},
		{"regular file", &Result{StatusCode: 200, URL: "http://a.com/file.txt"}, false},
		{"404", &Result{StatusCode: 404, URL: "http://a.com/nope"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDirectory(tt.result)
			if got != tt.expected {
				t.Errorf("isDirectory(%v) = %v, expected %v", tt.result, got, tt.expected)
			}
		})
	}
}

func TestExtractPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com/admin/panel", "/admin/panel"},
		{"http://example.com/", "/"},
		{"http://example.com", "/"},
		{"https://example.com/api/v1/users", "/api/v1/users"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractPath(tt.input)
			if got != tt.expected {
				t.Errorf("extractPath(%q) = %q, expected %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEngine405MethodFuzzing(t *testing.T) {
	var methodsSeen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/endpoint" {
			methodsSeen = append(methodsSeen, r.Method)
			if r.Method == "GET" {
				w.WriteHeader(405)
				return
			}
			if r.Method == "POST" {
				w.WriteHeader(200)
				w.Write([]byte("OK via POST"))
				return
			}
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	wordlistPath := createWordlist(t, "endpoint")

	cfg := config.Config{
		Wordlist:      wordlistPath,
		Threads:       1,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
	}

	engine := NewEngine(cfg)
	results, _, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	foundMethodResult := false
	for _, r := range results {
		if r.Method == "POST" {
			foundMethodResult = true
		}
	}

	if !foundMethodResult {
		t.Error("expected to find result with alternative method POST")
	}
}

func TestEngineBypassAttempt(t *testing.T) {
	var bypassHeaderSeen int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/protected" {
			if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
				atomic.AddInt32(&bypassHeaderSeen, 1)
				w.WriteHeader(200)
				w.Write([]byte("Bypassed!"))
				return
			}
			w.WriteHeader(403)
			w.Write([]byte("Forbidden"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	wordlistPath := createWordlist(t, "protected")

	cfg := config.Config{
		Wordlist:      wordlistPath,
		Threads:       1,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
	}

	engine := NewEngine(cfg)
	results, _, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	foundBypass := false
	for _, r := range results {
		if strings.Contains(r.URL, "BYPASS") || strings.Contains(r.Method, "BYPASS") {
			foundBypass = true
		}
	}

	if !foundBypass {
		t.Error("expected to find bypass result")
	}
}

func TestEngineCustomHeaders(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		if r.URL.Path == "/api" {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	wordlistPath := createWordlist(t, "api")

	cfg := config.Config{
		Wordlist:      wordlistPath,
		Threads:       1,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
		CustomHeaders: map[string]string{"Authorization": "Bearer test-token"},
	}

	engine := NewEngine(cfg)
	_, _, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if authHeader != "Bearer test-token" {
		t.Errorf("expected Authorization header, got %q", authHeader)
	}
}

func TestEngineWithExtensions(t *testing.T) {
	var pathsSeen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathsSeen = append(pathsSeen, r.URL.Path)
		if r.URL.Path == "/index.php" {
			w.WriteHeader(200)
			w.Write([]byte("PHP page"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	wordlistPath := createWordlist(t, "index")

	cfg := config.Config{
		Wordlist:      wordlistPath,
		Threads:       1,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
		Extensions:    []string{".php", ".html"},
	}

	engine := NewEngine(cfg)
	results, _, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	foundPHP := false
	for _, r := range results {
		if strings.HasSuffix(r.URL, "/index.php") {
			foundPHP = true
		}
	}

	if !foundPHP {
		t.Error("expected to find index.php result")
	}
}

func TestLoadWordlist(t *testing.T) {
	wordlistPath := createWordlist(t, "admin", "# comment", "", "api", "secret")

	words, err := loadWordlist(wordlistPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(words) != 3 {
		t.Errorf("expected 3 words (excluding comments and empty lines), got %d: %v", len(words), words)
	}
}

func TestLoadWordlist_NotFound(t *testing.T) {
	_, err := loadWordlist("/nonexistent/wordlist.txt")
	if err == nil {
		t.Error("expected error for nonexistent wordlist")
	}
}

func TestEngineMultipleTargets(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			w.Write([]byte("Server 1 Admin"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			w.Write([]byte("Server 2 Admin"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server2.Close()

	wordlistPath := createWordlist(t, "admin")

	cfg := config.Config{
		Wordlist:      wordlistPath,
		Threads:       2,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
	}

	engine := NewEngine(cfg)
	results, stats, err := engine.Run([]string{server1.URL, server2.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results (one per target), got %d", len(results))
	}

	if stats.GetFound() != 2 {
		t.Errorf("expected 2 found, got %d", stats.GetFound())
	}
}

func TestEngineSafeMode_NoBypass(t *testing.T) {
	bypassAttempted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/protected" {
			if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
				bypassAttempted = true
				w.WriteHeader(200)
				w.Write([]byte("Bypassed!"))
				return
			}
			w.WriteHeader(403)
			w.Write([]byte("Forbidden"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	wordlistPath := createWordlist(t, "protected")

	cfg := config.Config{
		Wordlist:      wordlistPath,
		Threads:       1,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
		SafeMode:      true,
	}

	engine := NewEngine(cfg)
	results, _, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if bypassAttempted {
		t.Error("safe mode should prevent bypass attempts")
	}

	for _, r := range results {
		if strings.Contains(r.URL, "BYPASS") || strings.Contains(r.Method, "BYPASS") {
			t.Error("safe mode should not produce bypass results")
		}
	}
}

func TestEngineSafeMode_NoMethodFuzzing(t *testing.T) {
	methodsSeen := make(map[string]bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/endpoint" {
			methodsSeen[r.Method] = true
			if r.Method == "GET" {
				w.WriteHeader(405)
				return
			}
			w.WriteHeader(200)
			w.Write([]byte("OK"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	wordlistPath := createWordlist(t, "endpoint")

	cfg := config.Config{
		Wordlist:      wordlistPath,
		Threads:       1,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
		SafeMode:      true,
	}

	engine := NewEngine(cfg)
	_, _, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for method := range methodsSeen {
		if method != "GET" {
			t.Errorf("safe mode should only use GET, saw %s", method)
		}
	}
}

func TestEngineResultsHaveSeverity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/page" {
			w.WriteHeader(200)
			w.Write([]byte("Hello"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	wordlistPath := createWordlist(t, "page")

	cfg := config.Config{
		Wordlist:      wordlistPath,
		Threads:       1,
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
	}

	engine := NewEngine(cfg)
	results, _, err := engine.Run([]string{server.URL})

	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, r := range results {
		if r.Severity == "" {
			t.Errorf("result %s should have severity assigned", r.URL)
		}
		if r.Confidence == "" {
			t.Errorf("result %s should have confidence assigned", r.URL)
		}
	}
}
