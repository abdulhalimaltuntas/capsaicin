package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/detection"
	"github.com/capsaicin/scanner/internal/transport"
)

// BypassStrategy defines a single bypass technique to try.
type BypassStrategy struct {
	Name    string
	Execute func(ctx context.Context, targetURL, userAgent string, cfg config.Config, client *transport.Client) (*Result, string)
}

// BypassResult wraps a successful bypass attempt with metadata about
// which strategy worked.
type BypassResult struct {
	Result   *Result
	Body     string
	Strategy string
}

// attemptBypassStrategies runs all configured bypass strategies against a 403/401
// URL until one succeeds or all are exhausted. Returns the first successful result.
// This replaces the old single-shot attemptBypass function with a multi-strategy approach.
func attemptBypassStrategies(ctx context.Context, originalURL, userAgent string, cfg config.Config, client *transport.Client) *BypassResult {
	path := extractPath(originalURL)
	baseURL := extractBaseURL(originalURL)

	strategies := buildBypassStrategies(baseURL, path)

	for _, strategy := range strategies {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		result, body := strategy.Execute(ctx, originalURL, userAgent, cfg, client)
		if result != nil && isBypassSuccess(result.StatusCode) {
			result.URL = originalURL + " [BYPASS:" + strategy.Name + "]"
			result.Method = "GET+BYPASS"
			return &BypassResult{
				Result:   result,
				Body:     body,
				Strategy: strategy.Name,
			}
		}
	}

	return nil
}

// buildBypassStrategies assembles the full list of bypass techniques to try.
func buildBypassStrategies(baseURL, path string) []BypassStrategy {
	strategies := []BypassStrategy{
		// 1. Header-based bypass — expanded set of IP spoofing & URL override headers
		headerBypass("headers", map[string]string{
			"X-Forwarded-For":           "127.0.0.1",
			"X-Forwarded-Host":          "127.0.0.1",
			"X-Original-URL":            path,
			"X-Rewrite-URL":             path,
			"X-Custom-IP-Authorization": "127.0.0.1",
			"Client-IP":                 "127.0.0.1",
			"True-Client-IP":            "127.0.0.1",
			"X-Real-IP":                 "127.0.0.1",
			"X-Remote-IP":               "127.0.0.1",
			"X-Remote-Addr":             "127.0.0.1",
			"X-ProxyUser-Ip":            "127.0.0.1",
			"X-Originating-IP":          "127.0.0.1",
		}),

		// 2. Path normalization — tricks that bypass path-based access control
		pathBypass("path-normalize", baseURL, path+"/."),
		pathBypass("path-dotslash", baseURL, "/./"+strings.TrimPrefix(path, "/")),
		pathBypass("path-double-slash", baseURL, "/"+strings.TrimPrefix(path, "/")),
		pathBypass("path-trailing-slash", baseURL, path+"/"),
		pathBypass("path-semicolon", baseURL, path+";"),
		pathBypass("path-semicolon-slash", baseURL, path+"..;/"),
		pathBypass("path-null-byte", baseURL, path+"%00"),
		pathBypass("path-hash", baseURL, path+"%23"),

		// 3. URL encoding — encode parts of the path
		urlEncodeBypass("url-encode", baseURL, path),

		// 4. Case manipulation — some ACLs are case-sensitive
		caseBypass("case-upper", baseURL, path),

		// 5. HTTP method override via header — some reverse proxies respect these
		methodOverrideBypass("method-override", path),
	}

	return strategies
}

// isBypassSuccess returns true if the status code indicates the bypass worked.
func isBypassSuccess(statusCode int) bool {
	return statusCode == 200 || statusCode == 302 || statusCode == 301
}

// ── Strategy builders ─────────────────────────────────────────────────────

// headerBypass creates a strategy that sends a GET request with extra bypass headers.
func headerBypass(name string, headers map[string]string) BypassStrategy {
	return BypassStrategy{
		Name: name,
		Execute: func(ctx context.Context, targetURL, userAgent string, cfg config.Config, client *transport.Client) (*Result, string) {
			req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			if err != nil {
				return nil, ""
			}

			req.Header.Set("User-Agent", userAgent)
			for key, value := range cfg.CustomHeaders {
				req.Header.Set(key, value)
			}
			for key, value := range headers {
				req.Header.Set(key, value)
			}

			return executeBypassRequest(req, cfg, client)
		},
	}
}

// pathBypass creates a strategy that requests a manipulated version of the original path.
func pathBypass(name, baseURL, altPath string) BypassStrategy {
	return BypassStrategy{
		Name: name,
		Execute: func(ctx context.Context, _, userAgent string, cfg config.Config, client *transport.Client) (*Result, string) {
			altURL := baseURL + altPath
			req, err := http.NewRequestWithContext(ctx, "GET", altURL, nil)
			if err != nil {
				return nil, ""
			}

			req.Header.Set("User-Agent", userAgent)
			for key, value := range cfg.CustomHeaders {
				req.Header.Set(key, value)
			}

			return executeBypassRequest(req, cfg, client)
		},
	}
}

// urlEncodeBypass encodes each character of the last segment of the path.
// e.g., /admin -> /%61%64%6d%69%6e
func urlEncodeBypass(name, baseURL, path string) BypassStrategy {
	return BypassStrategy{
		Name: name,
		Execute: func(ctx context.Context, _, userAgent string, cfg config.Config, client *transport.Client) (*Result, string) {
			encoded := encodePathSegment(path)
			altURL := baseURL + encoded

			req, err := http.NewRequestWithContext(ctx, "GET", altURL, nil)
			if err != nil {
				return nil, ""
			}

			// Prevent Go from normalizing our hand-crafted URL.
			req.URL = &url.URL{
				Scheme: req.URL.Scheme,
				Host:   req.URL.Host,
				Opaque: "//" + req.URL.Host + encoded,
			}

			req.Header.Set("User-Agent", userAgent)
			for key, value := range cfg.CustomHeaders {
				req.Header.Set(key, value)
			}

			return executeBypassRequest(req, cfg, client)
		},
	}
}

// caseBypass tries the path with the last segment's case swapped.
// /admin -> /Admin, /ADMIN, /aDMIN
func caseBypass(name, baseURL, path string) BypassStrategy {
	return BypassStrategy{
		Name: name,
		Execute: func(ctx context.Context, _, userAgent string, cfg config.Config, client *transport.Client) (*Result, string) {
			manipulated := manipulateCase(path)
			if manipulated == path {
				return nil, "" // no change possible
			}

			altURL := baseURL + manipulated
			req, err := http.NewRequestWithContext(ctx, "GET", altURL, nil)
			if err != nil {
				return nil, ""
			}

			req.Header.Set("User-Agent", userAgent)
			for key, value := range cfg.CustomHeaders {
				req.Header.Set(key, value)
			}

			return executeBypassRequest(req, cfg, client)
		},
	}
}

// methodOverrideBypass sends a GET but tells the server it's actually a different method
// via override headers (X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method).
func methodOverrideBypass(name, path string) BypassStrategy {
	return BypassStrategy{
		Name: name,
		Execute: func(ctx context.Context, targetURL, userAgent string, cfg config.Config, client *transport.Client) (*Result, string) {
			// Try POST body with method override headers
			req, err := http.NewRequestWithContext(ctx, "POST", targetURL, nil)
			if err != nil {
				return nil, ""
			}

			req.Header.Set("User-Agent", userAgent)
			req.Header.Set("X-HTTP-Method-Override", "GET")
			req.Header.Set("X-Method-Override", "GET")
			req.Header.Set("X-HTTP-Method", "GET")
			req.Header.Set("Content-Length", "0")

			for key, value := range cfg.CustomHeaders {
				req.Header.Set(key, value)
			}

			return executeBypassRequest(req, cfg, client)
		},
	}
}

// ── Helper functions ─────────────────────────────────────────────────────

// executeBypassRequest performs the HTTP request and assembles a Result.
func executeBypassRequest(req *http.Request, cfg config.Config, client *transport.Client) (*Result, string) {
	resp, body, err := client.DoContext(req.Context(), req, cfg.RateLimit)
	if err != nil {
		return nil, ""
	}

	bodyContent := string(body)
	result := &Result{
		URL:        req.URL.String(),
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(bodyContent)),
		LineCount:  strings.Count(bodyContent, "\n") + 1,
		Method:     req.Method,
		Timestamp:  time.Now().Format(time.RFC3339),
		Server:     resp.Header.Get("Server"),
		PoweredBy:  resp.Header.Get("X-Powered-By"),
	}

	if wafName := detection.DetectWAF(resp); wafName != "" {
		result.WAFDetected = wafName
	}

	return result, bodyContent
}

// extractBaseURL returns scheme + host from a full URL.
// e.g. "https://example.com/admin" -> "https://example.com"
func extractBaseURL(rawURL string) string {
	// Protocol-relative approach: find the third slash
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		return rawURL
	}
	rest := rawURL[idx+3:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return rawURL
	}
	return rawURL[:idx+3+slashIdx]
}

// encodePathSegment percent-encodes the last segment of the path.
// /api/admin -> /api/%61%64%6d%69%6e
func encodePathSegment(path string) string {
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash < 0 {
		return path
	}

	prefix := path[:lastSlash+1]
	segment := path[lastSlash+1:]

	if segment == "" {
		return path
	}

	var encoded strings.Builder
	encoded.WriteString(prefix)
	for _, ch := range segment {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			encoded.WriteString(fmt.Sprintf("%%%02x", ch))
		} else {
			encoded.WriteRune(ch)
		}
	}

	return encoded.String()
}

// manipulateCase toggles the case of the first character of the last path segment.
// /admin -> /Admin, /Admin -> /admin
func manipulateCase(path string) string {
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash < 0 || lastSlash >= len(path)-1 {
		return path
	}

	prefix := path[:lastSlash+1]
	segment := path[lastSlash+1:]
	first := rune(segment[0])

	if first >= 'a' && first <= 'z' {
		return prefix + strings.ToUpper(string(first)) + segment[1:]
	}
	if first >= 'A' && first <= 'Z' {
		return prefix + strings.ToLower(string(first)) + segment[1:]
	}

	return path
}
