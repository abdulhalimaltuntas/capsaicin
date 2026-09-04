package scanner

import (
	"testing"

	"github.com/capsaicin/scanner/internal/config"
)

func TestMatcher_FiltersAndMatchers(t *testing.T) {
	cfg := config.Config{MatchCodes: "200-299,301", FilterCodes: "204", FilterSize: "0", FilterWords: "1"}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		status, size, words int
		keep                bool
	}{
		{200, 100, 10, true},
		{301, 100, 10, true},
		{404, 100, 10, false}, // not in match codes
		{204, 100, 10, false}, // filtered code wins over match range
		{200, 0, 10, false},   // filtered size 0
		{200, 100, 1, false},  // filtered word count 1
	}
	for _, c := range cases {
		if got := m.Keep(c.status, c.size, c.words, ""); got != c.keep {
			t.Errorf("Keep(%d,%d,%d)=%v want %v", c.status, c.size, c.words, got, c.keep)
		}
	}
}

func TestMatcher_RegexAndEmptyDefault(t *testing.T) {
	m, _ := NewMatcher(config.Config{}) // no matchers/filters => keep all
	if !m.Keep(500, 10, 3, "x") {
		t.Error("empty matcher should keep everything")
	}
	mr, _ := NewMatcher(config.Config{MatchRegex: "admin"})
	if mr.Keep(200, 10, 3, "nothing here") {
		t.Error("regex matcher should exclude non-matching body")
	}
	if !mr.Keep(200, 10, 3, "the admin panel") {
		t.Error("regex matcher should keep matching body")
	}
}

func TestScope_AllowDeny(t *testing.T) {
	s := NewScope([]string{"*.example.com", "target.io"}, []string{"admin.example.com"})
	cases := map[string]bool{
		"www.example.com":   true,
		"api.example.com":   true,
		"admin.example.com": false, // deny wins
		"target.io":         true,
		"evil.com":          false, // not allowed
	}
	for host, want := range cases {
		if got := s.Allowed(host); got != want {
			t.Errorf("Allowed(%q)=%v want %v", host, got, want)
		}
	}
	if !NewScope(nil, nil).Allowed("anything.com") {
		t.Error("empty scope should allow all")
	}
}

func TestBuildURL_FuzzAndAppend(t *testing.T) {
	cases := []struct{ target, payload, want string }{
		{"https://x/FUZZ", "admin", "https://x/admin"},
		{"https://x/a/FUZZ/b", "admin", "https://x/a/admin/b"},
		{"https://x", "admin", "https://x/admin"},
		{"https://x/", "/admin", "https://x/admin"},
	}
	for _, c := range cases {
		if got := buildURL(c.target, c.payload); got != c.want {
			t.Errorf("buildURL(%q,%q)=%q want %q", c.target, c.payload, got, c.want)
		}
	}
}
