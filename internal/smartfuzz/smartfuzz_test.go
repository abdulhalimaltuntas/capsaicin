package smartfuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestExtractLinksSameHostOnly(t *testing.T) {
	body := `
		<a href="/admin">admin</a>
		<a href="/api/users">users</a>
		<a href="https://evil.com/steal">external</a>
		<a href="https://target.example/internal">same host absolute</a>
		<script src="/static/app.js"></script>
		<img src="/logo.png">
		<a href="mailto:a@b.com">mail</a>
		<a href="#section">anchor</a>
	`
	paths := ExtractLinks(body, "target.example")

	if !contains(paths, "/admin") || !contains(paths, "/api/users") {
		t.Errorf("expected in-scope paths, got %v", paths)
	}
	if !contains(paths, "/internal") {
		t.Errorf("expected same-host absolute path, got %v", paths)
	}
	if contains(paths, "/steal") {
		t.Errorf("external host path must be dropped, got %v", paths)
	}
	if contains(paths, "/logo.png") {
		t.Errorf("static asset must be dropped, got %v", paths)
	}
}

func TestExtractLinksStripsQuery(t *testing.T) {
	paths := ExtractLinks(`<a href="/search?q=1&page=2">s</a>`, "target.example")
	if !contains(paths, "/search") {
		t.Errorf("query string should be stripped, got %v", paths)
	}
}

func TestMutatorGeneratesVariants(t *testing.T) {
	m := NewMutator()
	variants := m.Mutate("admin")
	if len(variants) == 0 {
		t.Fatal("expected mutations for 'admin'")
	}
	if !contains(variants, "admin.bak") {
		t.Errorf("expected backup-extension variant, got sample %v", variants[:min(5, len(variants))])
	}
}

func TestSpiderCrawlRobotsAndHomepage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Write([]byte("User-agent: *\nDisallow: /secret-admin\nDisallow: /private-api\n"))
		case "/":
			w.Write([]byte(`<html><body><a href="/dashboard">d</a></body></html>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	spider := NewSpider(5 * time.Second)
	result, err := spider.Crawl(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("crawl failed: %v", err)
	}

	if !contains(result.Paths, "/secret-admin") {
		t.Errorf("expected robots.txt path, got %v", result.Paths)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
