package scanner

import "strings"

// Scope enforces --allow/--deny host rules so target-aware seeding (spider,
// link extraction, recursion) can never wander off the intended targets.
//
// A host is in scope when it matches at least one allow pattern (or no allow
// patterns are configured) AND matches no deny pattern. Patterns match against
// the host[:port] and support a leading/trailing "*" wildcard, e.g.
// "*.example.com", "example.*", "10.0.0.*".
type Scope struct {
	allow []string
	deny  []string
}

// NewScope builds a scope from the allow/deny pattern lists. Empty lists mean
// "allow everything", which preserves the pre-scope behavior.
func NewScope(allow, deny []string) *Scope {
	return &Scope{allow: normalizePatterns(allow), deny: normalizePatterns(deny)}
}

// Allowed reports whether a host is permitted by the scope rules.
func (s *Scope) Allowed(host string) bool {
	if s == nil {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))

	for _, d := range s.deny {
		if matchHostPattern(d, host) {
			return false
		}
	}
	if len(s.allow) == 0 {
		return true
	}
	for _, a := range s.allow {
		if matchHostPattern(a, host) {
			return true
		}
	}
	return false
}

// active reports whether any rule is configured (skip checks when not).
func (s *Scope) active() bool {
	return s != nil && (len(s.allow) > 0 || len(s.deny) > 0)
}

func normalizePatterns(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// matchHostPattern supports "*" as a leading and/or trailing wildcard, and a
// bare "*" meaning "any host".
func matchHostPattern(pattern, host string) bool {
	switch {
	case pattern == "*" || pattern == "":
		return pattern == "*"
	case strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*"):
		return strings.Contains(host, strings.Trim(pattern, "*"))
	case strings.HasPrefix(pattern, "*"):
		return strings.HasSuffix(host, strings.TrimPrefix(pattern, "*"))
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(host, strings.TrimSuffix(pattern, "*"))
	default:
		return host == pattern
	}
}
