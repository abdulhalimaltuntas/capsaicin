package scanner

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/abdulhalimaltuntas/capsaicin/internal/detection"
)

// pathBypassSuffixes are appended to a forbidden path's final segment to defeat
// naive path-based access controls (edge proxies / WAFs / app routers that match
// the literal request path but forward a normalized one to the origin).
var pathBypassSuffixes = []string{
	"/", "/.", "//", "/./", "%20", "%09", "%00", "?", "#", "..;/", ";/",
	".json", ".html", "~", "%2e", "/..;/", "?anything",
}

// pathBypassPrefixes wrap the path with segments a downstream normalizer collapses.
var pathBypassPrefixes = []string{"/", "//", "/./", "/%2e/"}

// pathBypassCandidates returns unique mutated URLs that attempt to slip past a
// path-based 401/403 gate for rawURL. The list is bounded (~25) to keep the extra
// request budget small. Each candidate keeps the scheme+host intact and only
// mutates the path.
func pathBypassCandidates(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return nil
	}

	origin := u.Scheme + "://" + u.Host
	path := u.Path
	trimmed := strings.TrimSuffix(path, "/")

	seen := make(map[string]bool)
	var out []string
	add := func(candidate string) {
		if candidate == "" || candidate == rawURL || seen[candidate] {
			return
		}
		seen[candidate] = true
		out = append(out, candidate)
	}

	// Suffix mutations on the final segment.
	for _, s := range pathBypassSuffixes {
		add(origin + trimmed + s)
	}

	// Prefix / wrapping mutations.
	seg := strings.TrimPrefix(trimmed, "/")
	for _, p := range pathBypassPrefixes {
		add(origin + p + seg)
	}

	// Case toggles of the last segment (matches case-sensitive ACLs on a
	// case-insensitive backend filesystem).
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		base, last := trimmed[:i+1], trimmed[i+1:]
		if last != "" {
			add(origin + base + strings.ToUpper(last))
			add(origin + base + capitalizeASCII(last))
		}
	}

	return out
}

// capitalizeASCII upper-cases only the first byte if it is an ASCII letter.
func capitalizeASCII(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-32) + s[1:]
}

// tryPathBypasses probes path-mutation variants of a forbidden URL and, on the
// first variant that yields a success/redirect (200/2xx/302), emits a critical
// bypass finding. It is bounded by both the candidate list and a soft deadline so
// a heavily-gated host cannot stall a worker.
func (wc *workerContext) tryPathBypasses(ctx context.Context, rawURL, userAgent, targetURL string) {
	candidates := pathBypassCandidates(rawURL)
	if len(candidates) == 0 {
		return
	}

	deadline := time.Now().Add(15 * time.Second)
	for _, candidate := range candidates {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if time.Now().After(deadline) {
			return
		}

		result, body, err := wc.makeRequest(ctx, candidate, "GET", "", userAgent, targetURL)
		if err != nil {
			continue
		}
		if result.StatusCode == 200 || result.StatusCode == 201 ||
			result.StatusCode == 204 || result.StatusCode == 302 {
			result.URL = rawURL + " [BYPASS-PATH:" + shortMutation(rawURL, candidate) + "]"
			result.Method = "GET+BYPASS"
			result.Critical = true
			result.Tags = appendUnique(result.Tags, "bypass-path")
			if secrets := detection.DetectSecrets(body); len(secrets) > 0 {
				result.SecretFound = true
				result.SecretTypes = secrets
				wc.stats.IncrementSecrets()
			}
			AssignSeverityAndConfidence(result)
			select {
			case wc.results <- *result:
			case <-ctx.Done():
			}
			return
		}
	}
}

// shortMutation returns the differing tail of candidate relative to rawURL, for a
// compact, human-readable label in the finding.
func shortMutation(rawURL, candidate string) string {
	cu, err1 := url.Parse(candidate)
	ru, err2 := url.Parse(rawURL)
	if err1 != nil || err2 != nil {
		return "mutated"
	}
	if cu.Path != ru.Path {
		return cu.Path
	}
	if cu.RawQuery != "" {
		return "?" + cu.RawQuery
	}
	return "mutated"
}
