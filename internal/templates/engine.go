package templates

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Response is the minimal response shape matchers evaluate against.
type Response struct {
	Status int
	Header http.Header
	Body   string
}

// FetchFunc issues a template request through the caller's transport.
type FetchFunc func(ctx context.Context, method, rawURL string, headers map[string]string, body string) (*Response, error)

// Match is a template hit.
type Match struct {
	TemplateID string
	Name       string
	Severity   string
	Tags       string
	URL        string
	Extracted  []string
}

// Engine runs a set of templates against target base URLs.
type Engine struct {
	Templates []*Template
	Fetch     FetchFunc
	// regex cache keyed by pattern to avoid recompiling across requests.
	reCache map[string]*regexp.Regexp
}

// NewEngine builds an engine over the given templates and fetcher.
func NewEngine(tmpls []*Template, fetch FetchFunc) *Engine {
	return &Engine{Templates: tmpls, Fetch: fetch, reCache: make(map[string]*regexp.Regexp)}
}

// RunAll evaluates every template against baseURL and returns all matches.
func (e *Engine) RunAll(ctx context.Context, baseURL string) []Match {
	var matches []Match
	for _, t := range e.Templates {
		select {
		case <-ctx.Done():
			return matches
		default:
		}
		matches = append(matches, e.runTemplate(ctx, t, baseURL)...)
	}
	return matches
}

// runTemplate evaluates one template's requests against baseURL.
func (e *Engine) runTemplate(ctx context.Context, t *Template, baseURL string) []Match {
	base := strings.TrimSuffix(baseURL, "/")
	var matches []Match

	for _, req := range t.resolvedRequests() {
		method := req.Method
		if method == "" {
			method = "GET"
		}
		paths := req.Path
		if len(paths) == 0 {
			paths = []string{"{{BaseURL}}"}
		}
		for _, p := range paths {
			select {
			case <-ctx.Done():
				return matches
			default:
			}
			rawURL := interpolate(p, base)
			headers := interpolateMap(req.Headers, base)
			body := interpolate(req.Body, base)

			resp, err := e.Fetch(ctx, method, rawURL, headers, body)
			if err != nil || resp == nil {
				continue
			}
			if e.evaluate(req, resp) {
				matches = append(matches, Match{
					TemplateID: t.ID,
					Name:       t.Info.Name,
					Severity:   t.severity(),
					Tags:       t.Info.Tags,
					URL:        rawURL,
					Extracted:  e.extract(req, resp),
				})
			}
		}
	}
	return matches
}

// evaluate applies a request's matchers with its and/or condition.
func (e *Engine) evaluate(req Request, resp *Response) bool {
	if len(req.Matchers) == 0 {
		return false
	}
	requireAll := strings.EqualFold(req.MatchersCondition, "and")
	for _, m := range req.Matchers {
		ok := e.matchOne(m, resp)
		if m.Negative {
			ok = !ok
		}
		if requireAll && !ok {
			return false
		}
		if !requireAll && ok {
			return true
		}
	}
	return requireAll // AND: all passed; OR: none passed
}

// matchOne evaluates a single matcher.
func (e *Engine) matchOne(m Matcher, resp *Response) bool {
	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if resp.Status == s {
				return true
			}
		}
		return false
	case "word":
		return matchWords(part(m.Part, resp), m.Words, m.Condition)
	case "header":
		return matchWords(headersString(resp.Header), m.Words, m.Condition)
	case "regex":
		return e.matchRegex(part(m.Part, resp), m.Regex, m.Condition)
	default:
		return false
	}
}

// matchWords applies substring matching across words with an and/or condition.
func matchWords(haystack string, words []string, condition string) bool {
	if len(words) == 0 {
		return false
	}
	all := strings.EqualFold(condition, "and")
	for _, w := range words {
		hit := strings.Contains(haystack, w)
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

// matchRegex applies regex matching across patterns with an and/or condition.
func (e *Engine) matchRegex(haystack string, patterns []string, condition string) bool {
	if len(patterns) == 0 {
		return false
	}
	all := strings.EqualFold(condition, "and")
	for _, p := range patterns {
		re := e.compile(p)
		hit := re != nil && re.MatchString(haystack)
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

// extract runs the request's extractors against a matched response.
func (e *Engine) extract(req Request, resp *Response) []string {
	var out []string
	seen := make(map[string]bool)
	for _, ex := range req.Extractors {
		if !strings.EqualFold(ex.Type, "regex") {
			continue
		}
		hay := part(ex.Part, resp)
		for _, p := range ex.Regex {
			re := e.compile(p)
			if re == nil {
				continue
			}
			for _, match := range re.FindAllStringSubmatch(hay, 8) {
				val := match[0]
				if len(match) > 1 && match[1] != "" {
					val = match[1]
				}
				if val != "" && !seen[val] {
					seen[val] = true
					out = append(out, val)
				}
			}
		}
	}
	return out
}

// compile returns a cached compiled regex, or nil for an invalid pattern.
func (e *Engine) compile(pattern string) *regexp.Regexp {
	if re, ok := e.reCache[pattern]; ok {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		e.reCache[pattern] = nil
		return nil
	}
	e.reCache[pattern] = re
	return re
}

// part selects the response segment a matcher inspects.
func part(name string, resp *Response) string {
	switch strings.ToLower(name) {
	case "header", "headers":
		return headersString(resp.Header)
	case "status":
		return strconv.Itoa(resp.Status)
	default: // body, all, ""
		return resp.Body
	}
}

// headersString serializes headers into a matchable "Key: Value" block.
func headersString(h http.Header) string {
	if h == nil {
		return ""
	}
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// interpolate substitutes the {{BaseURL}} placeholder.
func interpolate(s, base string) string {
	if s == "" {
		return s
	}
	return strings.ReplaceAll(s, "{{BaseURL}}", base)
}

// interpolateMap interpolates every value in a header map.
func interpolateMap(m map[string]string, base string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = interpolate(v, base)
	}
	return out
}
