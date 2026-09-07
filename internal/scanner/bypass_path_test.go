package scanner

import (
	"strings"
	"testing"
)

func TestPathBypassCandidates(t *testing.T) {
	got := pathBypassCandidates("https://example.com/admin")
	if len(got) == 0 {
		t.Fatal("expected candidates for /admin")
	}

	set := make(map[string]bool)
	for _, c := range got {
		set[c] = true
		if !strings.HasPrefix(c, "https://example.com") {
			t.Errorf("candidate left the origin: %q", c)
		}
	}

	// A few representative mutations must be present.
	for _, want := range []string{
		"https://example.com/admin/",
		"https://example.com/admin//",
		"https://example.com/admin/..;/",
		"https://example.com/ADMIN",
		"https://example.com//admin",
	} {
		if !set[want] {
			t.Errorf("expected mutation %q in candidates", want)
		}
	}

	// The original URL must never be re-emitted.
	if set["https://example.com/admin"] {
		t.Error("original URL should not be a candidate")
	}
}

func TestPathBypassCandidatesRootIsNoop(t *testing.T) {
	if got := pathBypassCandidates("https://example.com/"); got != nil {
		t.Errorf("root path should yield no candidates, got %v", got)
	}
	if got := pathBypassCandidates("https://example.com"); got != nil {
		t.Errorf("empty path should yield no candidates, got %v", got)
	}
}

func TestCapitalizeASCII(t *testing.T) {
	cases := map[string]string{
		"admin": "Admin",
		"Admin": "Admin",
		"1x":    "1x",
		"":      "",
	}
	for in, want := range cases {
		if got := capitalizeASCII(in); got != want {
			t.Errorf("capitalizeASCII(%q)=%q want %q", in, got, want)
		}
	}
}

func TestShortMutation(t *testing.T) {
	got := shortMutation("https://h/admin", "https://h/admin/")
	if got != "/admin/" {
		t.Errorf("shortMutation path diff = %q", got)
	}
	got = shortMutation("https://h/admin", "https://h/admin?x=1")
	if got != "?x=1" {
		t.Errorf("shortMutation query diff = %q", got)
	}
}
