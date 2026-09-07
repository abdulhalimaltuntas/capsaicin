// Package probes runs lightweight, safe active vulnerability checks against a
// discovered URL: open redirect, CRLF/header injection, local file inclusion /
// path traversal, and (out-of-band) SSRF. Each check is designed to confirm a
// class with a single deterministic signal and to avoid destructive payloads.
package probes

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Response is the minimal response shape the probers reason over.
type Response struct {
	Status   int
	Header   http.Header
	Body     string
	Location string
}

// FetchFunc issues one request with optional extra headers and returns a
// summarized response. Returning an error drops that probe.
type FetchFunc func(ctx context.Context, method, rawURL string, headers map[string]string) (*Response, error)

// Finding is one confirmed (or strongly-suspected) issue.
type Finding struct {
	Type     string // "open-redirect" | "crlf-injection" | "lfi" | "ssrf"
	Severity string // critical|high|medium
	URL      string
	Detail   string
}

// Prober bundles the checks and their shared configuration.
type Prober struct {
	Fetch     FetchFunc
	OOBDomain string // when set, SSRF payloads point here for out-of-band confirmation
}

// New returns a Prober using fetch for all requests.
func New(fetch FetchFunc, oobDomain string) *Prober {
	return &Prober{Fetch: fetch, OOBDomain: oobDomain}
}

// redirectParams are query keys frequently wired to server-side redirects.
var redirectParams = []string{"url", "next", "redirect", "redirect_uri", "return", "returnUrl", "dest", "destination", "continue", "target", "r", "u", "goto", "out", "link"}

// ssrfParams are query keys frequently wired to server-side fetches.
var ssrfParams = []string{"url", "uri", "path", "dest", "target", "src", "source", "callback", "webhook", "feed", "host", "site", "domain", "proxy", "fetch", "load"}

var passwdRe = regexp.MustCompile(`root:.*:0:0:`)

const (
	redirectCanary = "capsaicin.example.net"
	crlfHeaderName = "X-Capsaicin-Crlf"
)

// Run executes every applicable probe against rawURL and returns confirmed
// findings. It is best-effort and bounded by the caller's context.
func (p *Prober) Run(ctx context.Context, rawURL string) []Finding {
	if p.Fetch == nil {
		return nil
	}
	var out []Finding
	out = append(out, p.openRedirect(ctx, rawURL)...)
	out = append(out, p.crlf(ctx, rawURL)...)
	out = append(out, p.lfi(ctx, rawURL)...)
	if p.OOBDomain != "" {
		out = append(out, p.ssrf(ctx, rawURL)...)
	}
	return out
}

// openRedirect sets redirect-prone params to an external canary and flags a
// finding when the response redirects off-site to it.
func (p *Prober) openRedirect(ctx context.Context, rawURL string) []Finding {
	keys := paramKeys(rawURL, redirectParams)
	var out []Finding
	for _, k := range keys {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		test, err := setParam(rawURL, k, "https://"+redirectCanary)
		if err != nil {
			continue
		}
		resp, err := p.Fetch(ctx, "GET", test, nil)
		if err != nil || resp == nil {
			continue
		}
		loc := resp.Location
		if loc == "" {
			loc = resp.Header.Get("Location")
		}
		if resp.Status >= 300 && resp.Status < 400 && redirectsTo(loc, redirectCanary) {
			out = append(out, Finding{
				Type: "open-redirect", Severity: "medium", URL: test,
				Detail: "parameter '" + k + "' redirects to attacker-controlled host (" + loc + ")",
			})
			return out // one confirmation is enough
		}
	}
	return out
}

// crlf injects an encoded CRLF + marker header into redirect-prone params and
// flags a finding when the marker header is reflected into the response.
func (p *Prober) crlf(ctx context.Context, rawURL string) []Finding {
	payload := "%0d%0a" + crlfHeaderName + "%3a%20injected"
	keys := paramKeys(rawURL, redirectParams)
	var out []Finding
	for _, k := range keys {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		// Raw-encode the payload directly into the query so the CRLF survives.
		test, ok := rawSetParam(rawURL, k, payload)
		if !ok {
			continue
		}
		resp, err := p.Fetch(ctx, "GET", test, nil)
		if err != nil || resp == nil {
			continue
		}
		if resp.Header.Get(crlfHeaderName) != "" {
			out = append(out, Finding{
				Type: "crlf-injection", Severity: "high", URL: test,
				Detail: "parameter '" + k + "' allows response header injection (CRLF)",
			})
			return out
		}
	}
	return out
}

// lfi injects a traversal payload into path-like params and flags a finding when
// the response body contains an /etc/passwd signature.
func (p *Prober) lfi(ctx context.Context, rawURL string) []Finding {
	payloads := []string{"../../../../../../etc/passwd", "....//....//....//....//etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"}
	keys := paramKeys(rawURL, []string{"file", "path", "page", "template", "doc", "document", "include", "view", "load", "read", "download", "name"})
	var out []Finding
	for _, k := range keys {
		for _, pl := range payloads {
			select {
			case <-ctx.Done():
				return out
			default:
			}
			test, ok := rawSetParam(rawURL, k, pl)
			if !ok {
				continue
			}
			resp, err := p.Fetch(ctx, "GET", test, nil)
			if err != nil || resp == nil {
				continue
			}
			if passwdRe.MatchString(resp.Body) {
				out = append(out, Finding{
					Type: "lfi", Severity: "critical", URL: test,
					Detail: "parameter '" + k + "' discloses local files (/etc/passwd read)",
				})
				return out
			}
		}
	}
	return out
}

// ssrf points fetch-prone params at the configured OOB domain. Confirmation is
// out-of-band (the caller correlates DNS/HTTP hits), so this emits a high-severity
// candidate the operator verifies against their collaborator.
func (p *Prober) ssrf(ctx context.Context, rawURL string) []Finding {
	keys := paramKeys(rawURL, ssrfParams)
	var out []Finding
	for _, k := range keys {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		marker := strings.ReplaceAll(strings.ToLower(k), "_", "") + "." + p.OOBDomain
		test, err := setParam(rawURL, k, "http://"+marker+"/")
		if err != nil {
			continue
		}
		if _, err := p.Fetch(ctx, "GET", test, nil); err != nil {
			continue
		}
		out = append(out, Finding{
			Type: "ssrf", Severity: "high", URL: test,
			Detail: "parameter '" + k + "' issued an out-of-band request to " + marker + " — confirm via collaborator",
		})
	}
	return out
}

// paramKeys returns the union of a URL's existing query keys and a set of
// candidate keys, so probing covers both present and likely-hidden parameters.
func paramKeys(rawURL string, candidates []string) []string {
	seen := make(map[string]bool)
	var keys []string
	add := func(k string) {
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		keys = append(keys, k)
	}
	if u, err := url.Parse(rawURL); err == nil {
		for k := range u.Query() {
			add(k)
		}
	}
	for _, k := range candidates {
		add(k)
	}
	return keys
}

// setParam returns rawURL with key set to a properly-encoded value.
func setParam(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// rawSetParam splices key=value into the raw query verbatim (no percent
// re-encoding), so payloads containing pre-encoded CRLF/traversal survive intact.
func rawSetParam(rawURL, key, value string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	pair := key + "=" + value
	if u.RawQuery == "" {
		u.RawQuery = pair
	} else {
		u.RawQuery += "&" + pair
	}
	return u.String(), true
}

// redirectsTo reports whether a Location value points at the canary host.
func redirectsTo(location, canary string) bool {
	if location == "" {
		return false
	}
	if u, err := url.Parse(strings.TrimSpace(location)); err == nil && u.Host != "" {
		return strings.EqualFold(u.Host, canary)
	}
	return strings.Contains(location, canary)
}
