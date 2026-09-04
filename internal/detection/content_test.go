package detection

import (
	"net/http"
	"testing"
)

func TestClassifyContent(t *testing.T) {
	cases := []struct {
		url, body, wantTag string
	}{
		{"http://x/.git/config", "[core]\n\trepositoryformatversion = 0", "exposure-git"},
		{"http://x/.env", "API_KEY=abc123\nDB_PASS=secret", "env-file"},
		{"http://x/backup.sql", "INSERT INTO", "db-dump"},
		{"http://x/app.js.map", "{\"version\":3}", "source-map"},
		{"http://x/config.php.bak", "<?php", "backup-file"},
		{"http://x/wp-config.php", "<?php define('DB_NAME'", "sensitive-config"},
		{"http://x/uploads/", "<html><head><title>Index of /uploads</title>", "directory-listing"},
	}
	for _, c := range cases {
		tags := ClassifyContent(c.url, c.body)
		if !contains(tags, c.wantTag) {
			t.Errorf("ClassifyContent(%q) = %v; want tag %q", c.url, tags, c.wantTag)
		}
	}
	// .env without KEY=VALUE content should NOT flag (false-positive guard).
	if contains(ClassifyContent("http://x/.env", "<html>not an env file</html>"), "env-file") {
		t.Error("empty/HTML .env should not be flagged as env-file")
	}
}

func TestSecurityHeaderTags(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Access-Control-Allow-Origin", "*")
	perEP, hostP := SecurityHeaderTags(resp, true)
	if !contains(perEP, "cors-wildcard") {
		t.Errorf("expected cors-wildcard, got %v", perEP)
	}
	if !contains(hostP, "missing-hsts") || !contains(hostP, "missing-nosniff") {
		t.Errorf("expected missing-hsts + missing-nosniff, got %v", hostP)
	}
	// A well-secured response yields no posture tags.
	sec := &http.Response{Header: http.Header{}}
	sec.Header.Set("Strict-Transport-Security", "max-age=63072000")
	sec.Header.Set("X-Frame-Options", "DENY")
	sec.Header.Set("X-Content-Type-Options", "nosniff")
	_, hostP2 := SecurityHeaderTags(sec, true)
	if len(hostP2) != 0 {
		t.Errorf("secured response should have no posture tags, got %v", hostP2)
	}
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
