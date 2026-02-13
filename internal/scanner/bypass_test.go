package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/transport"
)

func TestExtractBaseURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/admin", "https://example.com"},
		{"http://example.com/api/v1/users", "http://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://sub.example.com:8443/path", "https://sub.example.com:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractBaseURL(tt.input)
			if got != tt.expected {
				t.Errorf("extractBaseURL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEncodePathSegment(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "/admin", "/%61%64%6d%69%6e"},
		{"nested", "/api/admin", "/api/%61%64%6d%69%6e"},
		{"empty segment", "/", "/"},
		{"mixed", "/test123", "/%74%65%73%74123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodePathSegment(tt.input)
			if got != tt.expected {
				t.Errorf("encodePathSegment(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestManipulateCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/admin", "/Admin"},
		{"/Admin", "/admin"},
		{"/api/config", "/api/Config"},
		{"/", "/"},
		{"/123", "/123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := manipulateCase(tt.input)
			if got != tt.expected {
				t.Errorf("manipulateCase(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsBypassSuccess(t *testing.T) {
	tests := []struct {
		code     int
		expected bool
	}{
		{200, true},
		{301, true},
		{302, true},
		{403, false},
		{401, false},
		{404, false},
		{500, false},
	}

	for _, tt := range tests {
		got := isBypassSuccess(tt.code)
		if got != tt.expected {
			t.Errorf("isBypassSuccess(%d) = %v, want %v", tt.code, got, tt.expected)
		}
	}
}

func TestBuildBypassStrategies(t *testing.T) {
	strategies := buildBypassStrategies("https://example.com", "/admin")
	if len(strategies) == 0 {
		t.Fatal("expected at least one bypass strategy")
	}

	// Check that we have the expected named strategies
	names := make(map[string]bool)
	for _, s := range strategies {
		names[s.Name] = true
	}

	expectedNames := []string{"headers", "path-normalize", "path-dotslash", "path-double-slash",
		"path-trailing-slash", "path-semicolon", "url-encode", "case-upper", "method-override"}
	for _, name := range expectedNames {
		if !names[name] {
			t.Errorf("missing expected strategy %q", name)
		}
	}
}

func TestAttemptBypassStrategies_HeaderBypass(t *testing.T) {
	// Server returns 403 normally, 200 when X-Forwarded-For is 127.0.0.1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			w.WriteHeader(200)
			w.Write([]byte("bypassed"))
			return
		}
		w.WriteHeader(403)
		w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	cfg := testBypassConfig()
	client := testBypassClient()

	result := attemptBypassStrategies(
		context.Background(),
		server.URL+"/admin",
		"test-agent",
		cfg,
		client,
	)

	if result == nil {
		t.Fatal("expected bypass to succeed via header injection")
	}
	if result.Strategy != "headers" {
		t.Errorf("expected strategy 'headers', got %q", result.Strategy)
	}
	if result.Result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.Result.StatusCode)
	}
	if !strings.Contains(result.Result.URL, "[BYPASS:headers]") {
		t.Errorf("expected BYPASS tag in URL, got %q", result.Result.URL)
	}
}

func TestAttemptBypassStrategies_PathBypass(t *testing.T) {
	// Server returns 403 for /admin, 200 for /admin/.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.") || strings.HasSuffix(r.URL.Path, "/./") {
			w.WriteHeader(200)
			w.Write([]byte("bypassed via path"))
			return
		}
		w.WriteHeader(403)
	}))
	defer server.Close()

	cfg := testBypassConfig()
	client := testBypassClient()

	result := attemptBypassStrategies(
		context.Background(),
		server.URL+"/admin",
		"test-agent",
		cfg,
		client,
	)

	if result == nil {
		t.Fatal("expected bypass to succeed via path normalization")
	}
	if !strings.Contains(result.Strategy, "path") {
		t.Errorf("expected a path-based strategy, got %q", result.Strategy)
	}
}

func TestAttemptBypassStrategies_AllFail(t *testing.T) {
	// Server always returns 403
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	cfg := testBypassConfig()
	client := testBypassClient()

	result := attemptBypassStrategies(
		context.Background(),
		server.URL+"/admin",
		"test-agent",
		cfg,
		client,
	)

	if result != nil {
		t.Errorf("expected nil result when all strategies fail, got strategy=%q", result.Strategy)
	}
}

func TestAttemptBypassStrategies_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer server.Close()

	cfg := testBypassConfig()
	client := testBypassClient()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	result := attemptBypassStrategies(
		ctx,
		server.URL+"/admin",
		"test-agent",
		cfg,
		client,
	)

	if result != nil {
		t.Error("expected nil result when context is cancelled")
	}
}

func TestAttemptBypassStrategies_CaseBypass(t *testing.T) {
	// Server has case-sensitive ACL: /admin -> 403, /Admin -> 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/Admin" {
			w.WriteHeader(200)
			w.Write([]byte("case bypass worked"))
			return
		}
		w.WriteHeader(403)
	}))
	defer server.Close()

	cfg := testBypassConfig()
	client := testBypassClient()

	result := attemptBypassStrategies(
		context.Background(),
		server.URL+"/admin",
		"test-agent",
		cfg,
		client,
	)

	if result == nil {
		t.Fatal("expected bypass to succeed via case manipulation")
	}
	if result.Strategy != "case-upper" {
		t.Errorf("expected strategy 'case-upper', got %q", result.Strategy)
	}
}

func TestAttemptBypassStrategies_MethodOverride(t *testing.T) {
	// Server returns 403 for GET, but 200 for POST with X-HTTP-Method-Override
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.Header.Get("X-HTTP-Method-Override") == "GET" {
			w.WriteHeader(200)
			w.Write([]byte("method override bypass"))
			return
		}
		w.WriteHeader(403)
	}))
	defer server.Close()

	cfg := testBypassConfig()
	client := testBypassClient()

	result := attemptBypassStrategies(
		context.Background(),
		server.URL+"/admin",
		"test-agent",
		cfg,
		client,
	)

	if result == nil {
		t.Fatal("expected bypass to succeed via method override")
	}
	if result.Strategy != "method-override" {
		t.Errorf("expected strategy 'method-override', got %q", result.Strategy)
	}
}

// ── test helpers ─────────────────────────────────────────────────────────

func testBypassConfig() config.Config {
	return config.Config{
		Timeout:       10,
		RateLimit:     0,
		RetryAttempts: 0,
		MaxResponseMB: 10,
		CustomHeaders: make(map[string]string),
	}
}

func testBypassClient() *transport.Client {
	return transport.NewClient(10, 0, 0, 10)
}
