package scanner

import "strings"

// Scope enforces --allow/--deny host rules so target-aware seeding (spider,
// link extraction, recursion) can never wander off the intended targets.
//
// A host is in scope when it matches at least one allow pattern (or no allow
// patterns are configured) AND matches no deny pattern. Patterns match against
// the host and, independently, the host with its port stripped — so a portless
// pattern matches regardless of the target's port. They support a
// leading/trailing "*" wildcard, e.g. "*.example.com", "example.*", "10.0.0.*".
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
	// hostOf() yields host[:port]; match patterns against both the full value
	// and the port-stripped host so a portless pattern (`--deny 127.0.0.1`,
	// `--allow *.example.com`) still matches a target served on a non-default
	// port (127.0.0.1:18090). A deny that silently failed to match because of a
	// port would be dangerous: the operator believes a host is excluded while it
	// is still being hit.
	noPort := stripPort(host)
	match := func(pattern string) bool {
		if matchHostPattern(pattern, host) {
			return true
		}
		return noPort != host && matchHostPattern(pattern, noPort)
	}

	for _, d := range s.deny {
		if match(d) {
			return false
		}
	}
	if len(s.allow) == 0 {
		return true
	}
	for _, a := range s.allow {
		if match(a) {
			return true
		}
	}
	return false
}

// stripPort removes a trailing :port from a host, handling bracketed IPv6
// literals ([::1]:8080 → ::1). A host with no port is returned unchanged.
func stripPort(host string) string {
	if host == "" {
		return host
	}
	if strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, "]"); i >= 0 {
			return host[1:i]
		}
		return host
	}
	if i := strings.LastIndex(host, ":"); i >= 0 {
		return host[:i]
	}
	return host
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
