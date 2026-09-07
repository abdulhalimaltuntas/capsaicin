package passive

import (
	"context"
	"testing"
)

func TestPathOf(t *testing.T) {
	tests := []struct {
		url, host, want string
	}{
		{"https://example.com/admin/panel", "example.com", "admin/panel"},
		{"https://api.example.com/v1/users", "example.com", "v1/users"}, // subdomain in-scope
		{"https://example.com/search?q=1", "example.com", "search?q=1"},
		{"https://evil.com/x", "example.com", ""},   // out of scope
		{"https://example.com/", "example.com", ""}, // root only
		{"not a url", "example.com", ""},
		{"", "example.com", ""},
	}
	for _, tt := range tests {
		if got := pathOf(tt.url, tt.host); got != tt.want {
			t.Errorf("pathOf(%q,%q)=%q want %q", tt.url, tt.host, got, tt.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"https://example.com/path": "example.com",
		"http://example.com:8080":  "example.com",
		"example.com":              "example.com",
		"example.com/foo":          "example.com",
		"EXAMPLE.com":              "example.com",
		"":                         "",
	}
	for in, want := range tests {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNewDefaults(t *testing.T) {
	c := New(0)
	if c.Timeout <= 0 || c.HTTP == nil || c.MaxPerSource <= 0 {
		t.Errorf("New(0) did not apply defaults: %+v", c)
	}
}

func TestCollectEmptyHost(t *testing.T) {
	// An unparseable/empty host short-circuits without any network calls.
	c := New(1)
	res := c.Collect(context.Background(), "")
	if res == nil || len(res.Paths) != 0 || len(res.Subdomains) != 0 {
		t.Errorf("empty host should yield empty result, got %+v", res)
	}
}
