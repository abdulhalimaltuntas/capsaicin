package smartfuzz

import (
	"regexp"
	"strings"
)

// linkAttrRegex captures href/src/action attribute values.
var linkAttrRegex = regexp.MustCompile(`(?:href|src|action|data-url)=["']([^"'<>]+)["']`)

// jsPathRegex captures quoted absolute paths that look like routes/endpoints
// embedded in inline scripts or JSON blobs.
var jsPathRegex = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-./]{2,80})["']`)

// ExtractLinks pulls same-host, in-scope paths out of an HTML or JS response
// body for on-the-fly endpoint discovery. It returns clean, deduplicated
// paths beginning with "/", excluding assets that are not useful to re-fuzz.
//
// host is the target host (e.g. "example.com"); links pointing at other hosts
// are dropped to keep the scan in scope.
func ExtractLinks(body, host string) []string {
	seen := make(map[string]bool)
	var paths []string

	add := func(raw string) {
		p := normalizeLink(raw, host)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}

	for _, m := range linkAttrRegex.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	for _, m := range jsPathRegex.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	return paths
}

// normalizeLink converts a raw link into an in-scope absolute path, or "" if
// it should be skipped (external host, fragment, mailto, static asset, etc.).
func normalizeLink(raw, host string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Skip non-navigational schemes and fragments.
	lower := strings.ToLower(raw)
	for _, bad := range []string{"mailto:", "tel:", "javascript:", "data:", "#"} {
		if strings.HasPrefix(lower, bad) {
			return ""
		}
	}

	// Absolute URL: keep only if same host.
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		u := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
		u = strings.TrimPrefix(u, "http://")
		idx := strings.Index(u, "/")
		if idx < 0 {
			return ""
		}
		linkHost := u[:idx]
		if host != "" && !strings.EqualFold(linkHost, host) {
			return ""
		}
		raw = u[idx:]
	} else if strings.HasPrefix(raw, "//") {
		// Protocol-relative — treat as external unless same host.
		u := raw[2:]
		idx := strings.Index(u, "/")
		if idx < 0 {
			return ""
		}
		if host != "" && !strings.EqualFold(u[:idx], host) {
			return ""
		}
		raw = u[idx:]
	} else if !strings.HasPrefix(raw, "/") {
		// Relative path — skip; base resolution is ambiguous and noisy.
		return ""
	}

	// Strip query strings and fragments.
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/" {
		return ""
	}

	// Drop obvious static assets that add noise without value.
	if isStaticAsset(raw) {
		return ""
	}
	return raw
}

var staticAssetExts = []string{
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
	".css", ".woff", ".woff2", ".ttf", ".eot", ".map",
	".mp4", ".webm", ".mp3", ".pdf",
}

func isStaticAsset(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range staticAssetExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
