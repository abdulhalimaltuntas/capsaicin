package probes

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestOpenRedirect(t *testing.T) {
	fetch := func(_ context.Context, _, rawURL string, _ map[string]string) (*Response, error) {
		// Reflect the "next" param into a Location redirect.
		if strings.Contains(rawURL, redirectCanary) {
			return &Response{Status: 302, Header: http.Header{}, Location: "https://" + redirectCanary + "/"}, nil
		}
		return &Response{Status: 200, Header: http.Header{}}, nil
	}
	p := New(fetch, "")
	findings := p.openRedirect(context.Background(), "https://target/go?next=1")
	if len(findings) != 1 || findings[0].Type != "open-redirect" {
		t.Fatalf("expected open-redirect finding, got %+v", findings)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("open-redirect should be medium, got %s", findings[0].Severity)
	}
}

func TestCRLF(t *testing.T) {
	fetch := func(_ context.Context, _, rawURL string, _ map[string]string) (*Response, error) {
		h := http.Header{}
		// Simulate the origin reflecting an injected header.
		if strings.Contains(rawURL, crlfHeaderName) {
			h.Set(crlfHeaderName, "injected")
		}
		return &Response{Status: 200, Header: h}, nil
	}
	p := New(fetch, "")
	findings := p.crlf(context.Background(), "https://target/x?url=1")
	if len(findings) != 1 || findings[0].Type != "crlf-injection" {
		t.Fatalf("expected crlf finding, got %+v", findings)
	}
}

func TestLFI(t *testing.T) {
	fetch := func(_ context.Context, _, rawURL string, _ map[string]string) (*Response, error) {
		body := "nothing"
		if strings.Contains(rawURL, "passwd") {
			body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1"
		}
		return &Response{Status: 200, Header: http.Header{}, Body: body}, nil
	}
	p := New(fetch, "")
	findings := p.lfi(context.Background(), "https://target/view?file=home")
	if len(findings) != 1 || findings[0].Type != "lfi" {
		t.Fatalf("expected lfi finding, got %+v", findings)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("lfi should be critical, got %s", findings[0].Severity)
	}
}

func TestSSRFRequiresOOB(t *testing.T) {
	fetch := func(_ context.Context, _, _ string, _ map[string]string) (*Response, error) {
		return &Response{Status: 200, Header: http.Header{}}, nil
	}
	// Without an OOB domain, Run must not emit SSRF findings.
	p := New(fetch, "")
	for _, f := range p.Run(context.Background(), "https://target/fetch?url=x") {
		if f.Type == "ssrf" {
			t.Error("ssrf should not fire without an OOB domain")
		}
	}
	// With an OOB domain, ssrf emits candidates.
	p = New(fetch, "oob.example.com")
	findings := p.ssrf(context.Background(), "https://target/fetch?url=x")
	if len(findings) == 0 {
		t.Error("expected ssrf candidate with OOB domain configured")
	}
}

func TestParamKeys(t *testing.T) {
	keys := paramKeys("https://h/p?custom=1&id=2", []string{"url", "id"})
	set := map[string]bool{}
	for _, k := range keys {
		set[k] = true
	}
	// Union of existing query keys and candidates, deduplicated.
	for _, want := range []string{"custom", "id", "url"} {
		if !set[want] {
			t.Errorf("expected key %q in %v", want, keys)
		}
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 unique keys, got %d (%v)", len(keys), keys)
	}
}

func TestRawSetParamPreservesPayload(t *testing.T) {
	out, ok := rawSetParam("https://h/p", "file", "..%2f..%2fetc%2fpasswd")
	if !ok || !strings.Contains(out, "..%2f..%2fetc%2fpasswd") {
		t.Errorf("rawSetParam must not re-encode payload: %s", out)
	}
}

func TestRedirectsTo(t *testing.T) {
	if !redirectsTo("https://capsaicin.example.net/x", "capsaicin.example.net") {
		t.Error("should detect canary host redirect")
	}
	if redirectsTo("https://legit.com/", "capsaicin.example.net") {
		t.Error("should not flag unrelated redirect")
	}
}
