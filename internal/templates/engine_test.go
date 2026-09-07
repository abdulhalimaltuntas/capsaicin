package templates

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// mockFetch returns a fixed response for every request.
func mockFetch(resp *Response) FetchFunc {
	return func(_ context.Context, _, rawURL string, _ map[string]string, _ string) (*Response, error) {
		r := *resp
		return &r, nil
	}
}

func TestLoadDirAndRun(t *testing.T) {
	dir := t.TempDir()
	yaml := `
id: git-config-exposure
info:
  name: Exposed .git/config
  severity: high
  tags: exposure,git
requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "[core]"
`
	if err := os.WriteFile(filepath.Join(dir, "git.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	tmpls, errs := LoadDir(dir)
	if len(errs) != 0 {
		t.Fatalf("unexpected load errors: %v", errs)
	}
	if len(tmpls) != 1 || tmpls[0].ID != "git-config-exposure" {
		t.Fatalf("template not loaded correctly: %+v", tmpls)
	}

	fetch := mockFetch(&Response{Status: 200, Header: http.Header{}, Body: "[core]\nrepositoryformatversion = 0"})
	eng := NewEngine(tmpls, fetch)
	matches := eng.RunAll(context.Background(), "https://target")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Severity != "high" || matches[0].TemplateID != "git-config-exposure" {
		t.Errorf("unexpected match metadata: %+v", matches[0])
	}
}

func TestMatchersConditionAnd(t *testing.T) {
	req := Request{
		MatchersCondition: "and",
		Matchers: []Matcher{
			{Type: "status", Status: []int{200}},
			{Type: "word", Part: "body", Words: []string{"admin"}},
		},
	}
	eng := NewEngine(nil, nil)
	if !eng.evaluate(req, &Response{Status: 200, Body: "admin panel"}) {
		t.Error("AND: both matchers satisfied should pass")
	}
	if eng.evaluate(req, &Response{Status: 200, Body: "nothing"}) {
		t.Error("AND: one matcher failing should fail")
	}
}

func TestMatchersConditionOr(t *testing.T) {
	req := Request{
		MatchersCondition: "or",
		Matchers: []Matcher{
			{Type: "status", Status: []int{500}},
			{Type: "word", Part: "body", Words: []string{"secret"}},
		},
	}
	eng := NewEngine(nil, nil)
	if !eng.evaluate(req, &Response{Status: 200, Body: "the secret is here"}) {
		t.Error("OR: one matcher satisfied should pass")
	}
	if eng.evaluate(req, &Response{Status: 200, Body: "clean"}) {
		t.Error("OR: no matcher satisfied should fail")
	}
}

func TestMatcherNegative(t *testing.T) {
	req := Request{
		Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"error"}, Negative: true}},
	}
	eng := NewEngine(nil, nil)
	if !eng.evaluate(req, &Response{Status: 200, Body: "all good"}) {
		t.Error("negative word matcher should pass when word absent")
	}
	if eng.evaluate(req, &Response{Status: 200, Body: "fatal error"}) {
		t.Error("negative word matcher should fail when word present")
	}
}

func TestMatcherRegexAndHeader(t *testing.T) {
	eng := NewEngine(nil, nil)
	regexReq := Request{Matchers: []Matcher{{Type: "regex", Part: "body", Regex: []string{`v\d+\.\d+\.\d+`}}}}
	if !eng.evaluate(regexReq, &Response{Body: "app version v1.2.3 running"}) {
		t.Error("regex matcher should match version string")
	}
	h := http.Header{}
	h.Set("X-Powered-By", "Express")
	headerReq := Request{Matchers: []Matcher{{Type: "header", Words: []string{"Express"}}}}
	if !eng.evaluate(headerReq, &Response{Header: h}) {
		t.Error("header matcher should match X-Powered-By value")
	}
}

func TestExtractors(t *testing.T) {
	req := Request{
		Matchers:   []Matcher{{Type: "status", Status: []int{200}}},
		Extractors: []Extractor{{Type: "regex", Part: "body", Regex: []string{`token=([a-z0-9]+)`}}},
	}
	eng := NewEngine([]*Template{{ID: "t", Requests: []Request{req}}}, mockFetch(&Response{Status: 200, Body: "token=abc123 more"}))
	matches := eng.RunAll(context.Background(), "https://h")
	if len(matches) != 1 || len(matches[0].Extracted) != 1 || matches[0].Extracted[0] != "abc123" {
		t.Fatalf("extractor failed: %+v", matches)
	}
}

// TestBuiltinTemplatesValid guards the shipped example templates: every YAML in
// the repo's templates/ directory must parse and carry at least one request.
func TestBuiltinTemplatesValid(t *testing.T) {
	tmpls, errs := LoadDir("../../templates")
	for _, err := range errs {
		t.Errorf("shipped template failed to load: %v", err)
	}
	if len(tmpls) == 0 {
		t.Skip("no shipped templates found (running outside repo tree)")
	}
	for _, tmpl := range tmpls {
		if tmpl.ID == "" {
			t.Errorf("template missing id: %+v", tmpl)
		}
		if len(tmpl.resolvedRequests()) == 0 {
			t.Errorf("template %s has no requests", tmpl.ID)
		}
	}
}

func TestLoadInvalidTemplate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("id: broken\ninfo: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errs := LoadDir(dir)
	if len(errs) != 1 {
		t.Errorf("expected 1 load error for template without requests, got %v", errs)
	}
}
