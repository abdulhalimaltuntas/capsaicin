package detection

import (
	"net/http"
	"testing"
)

func respWith(headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{Header: h}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func TestTechFingerprintServerHeader(t *testing.T) {
	tags := TechFingerprint(respWith(map[string]string{
		"Server":       "nginx/1.25.1",
		"X-Powered-By": "PHP/8.2.1",
	}))
	if !hasTag(tags, "nginx") {
		t.Errorf("expected nginx tag, got %v", tags)
	}
	if !hasTag(tags, "PHP") {
		t.Errorf("expected PHP tag, got %v", tags)
	}
}

func TestTechFingerprintFrameworkHeaders(t *testing.T) {
	tags := TechFingerprint(respWith(map[string]string{
		"X-AspNet-Version": "4.0.30319",
	}))
	if !hasTag(tags, "ASP.NET") {
		t.Errorf("expected ASP.NET tag from X-AspNet-Version, got %v", tags)
	}
}

func TestTechFingerprintCookies(t *testing.T) {
	tags := TechFingerprint(respWith(map[string]string{
		"Set-Cookie": "laravel_session=abc; path=/",
	}))
	if !hasTag(tags, "Laravel") {
		t.Errorf("expected Laravel tag from cookie, got %v", tags)
	}
}

func TestTechFingerprintNil(t *testing.T) {
	if TechFingerprint(nil) != nil {
		t.Error("nil response should yield nil tags")
	}
}

func TestSuggestExtensions(t *testing.T) {
	exts := SuggestExtensions([]string{"PHP", "WordPress"})
	found := false
	for _, e := range exts {
		if e == ".php" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected .php suggestion for PHP stack, got %v", exts)
	}
}
