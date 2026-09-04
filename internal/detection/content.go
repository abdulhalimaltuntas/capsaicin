package detection

import (
	"net/http"
	"strings"
)

// ClassifyContent inspects a discovered URL and its body for sensitive-content
// signals (exposed VCS/config/backup files, directory listings) and returns
// descriptive tags. The scoring layer maps these tags to severities. Tags are
// intentionally conservative: path hints are confirmed against body content
// where a cheap check exists, to keep false positives low.
func ClassifyContent(urlStr, body string) []string {
	var tags []string
	add := func(t string) { tags = append(tags, t) }

	lp := strings.ToLower(urlStr)
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	lhead := strings.ToLower(head)

	switch {
	case strings.Contains(lp, "/.git/config") || strings.HasSuffix(lp, "/.git/head"):
		if strings.Contains(lhead, "[core]") || strings.HasPrefix(strings.TrimSpace(lhead), "ref:") {
			add("exposure-git")
		}
	case strings.Contains(lp, "/.git/"):
		add("exposure-git")
	case strings.Contains(lp, "/.svn/"):
		add("exposure-svn")
	case strings.Contains(lp, "/.hg/"):
		add("exposure-hg")
	}

	if strings.HasSuffix(lp, "/.env") || strings.HasSuffix(lp, ".env") {
		if looksLikeEnvFile(head) {
			add("env-file")
		}
	}

	for _, s := range []string{"wp-config.php", "web.config", ".htpasswd", ".htaccess",
		"id_rsa", "id_dsa", ".ssh/", "credentials", ".aws/", ".npmrc", ".dockercfg",
		"docker-compose.yml", "config.php.bak"} {
		if strings.Contains(lp, s) {
			add("sensitive-config")
			break
		}
	}

	for _, ext := range []string{".bak", ".old", ".backup", ".orig", ".save", ".swp", ".tmp", "~"} {
		if strings.HasSuffix(lp, ext) {
			add("backup-file")
			break
		}
	}
	if strings.HasSuffix(lp, ".map") || strings.HasSuffix(lp, ".js.map") {
		add("source-map")
	}
	if strings.HasSuffix(lp, ".sql") || strings.HasSuffix(lp, ".sql.gz") || strings.HasSuffix(lp, ".dump") {
		add("db-dump")
	}

	if isDirectoryListing(lhead) {
		add("directory-listing")
	}

	return tags
}

func looksLikeEnvFile(head string) bool {
	lines := strings.Split(head, "\n")
	kv := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if i := strings.Index(l, "="); i > 0 && !strings.Contains(l[:i], " ") {
			kv++
		}
	}
	return kv >= 2
}

func isDirectoryListing(lhead string) bool {
	return strings.Contains(lhead, "<title>index of") ||
		strings.Contains(lhead, "<h1>index of") ||
		strings.Contains(lhead, "directory listing for")
}

// SecurityHeaderTags audits a response's security headers. CORS wildcard is a
// per-endpoint finding; the missing-header signals are host-level posture and
// the caller should emit them once per host to avoid noise.
func SecurityHeaderTags(resp *http.Response, isHTTPS bool) (perEndpoint, hostPosture []string) {
	if resp == nil {
		return nil, nil
	}
	h := resp.Header

	if acao := h.Get("Access-Control-Allow-Origin"); acao == "*" {
		perEndpoint = append(perEndpoint, "cors-wildcard")
	}

	if isHTTPS && h.Get("Strict-Transport-Security") == "" {
		hostPosture = append(hostPosture, "missing-hsts")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		hostPosture = append(hostPosture, "missing-xfo")
	}
	if !strings.EqualFold(h.Get("X-Content-Type-Options"), "nosniff") {
		hostPosture = append(hostPosture, "missing-nosniff")
	}
	return perEndpoint, hostPosture
}
