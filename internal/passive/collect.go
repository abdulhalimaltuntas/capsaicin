// Package passive seeds a scan from public intelligence sources without touching
// the target: the Wayback Machine, AlienVault OTX, urlscan.io, and crt.sh. It
// returns historical URLs (mined for in-scope paths) and observed subdomains,
// dramatically widening the attack surface at zero cost to the target.
package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Result holds everything the passive collectors found for a host.
type Result struct {
	Paths      []string // in-scope URL paths (deduplicated, leading slash trimmed)
	Subdomains []string // observed subdomains of the host
	Sources    []string // which sources returned data (for reporting)
}

// Collector queries the public sources. A nil HTTP client falls back to a
// timeout-bounded default.
type Collector struct {
	HTTP    *http.Client
	Timeout time.Duration
	// MaxPerSource bounds how many entries are read from any one source so a
	// noisy domain cannot balloon the queue.
	MaxPerSource int
}

// New returns a Collector with sensible defaults.
func New(timeout time.Duration) *Collector {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Collector{
		HTTP:         &http.Client{Timeout: timeout},
		Timeout:      timeout,
		MaxPerSource: 5000,
	}
}

// Collect runs every source concurrently and merges their results. It is
// best-effort: a failing source is skipped, never fatal.
func (c *Collector) Collect(ctx context.Context, host string) *Result {
	host = normalizeHost(host)
	if host == "" {
		return &Result{}
	}

	type sourceResult struct {
		name  string
		paths []string
		subs  []string
	}
	sources := []struct {
		name string
		fn   func(context.Context, string) ([]string, []string)
	}{
		{"wayback", c.wayback},
		{"otx", c.otx},
		{"urlscan", c.urlscan},
		{"crtsh", c.crtsh},
	}

	ch := make(chan sourceResult, len(sources))
	for _, s := range sources {
		s := s
		go func() {
			paths, subs := s.fn(ctx, host)
			ch <- sourceResult{name: s.name, paths: paths, subs: subs}
		}()
	}

	res := &Result{}
	seenPath := make(map[string]bool)
	seenSub := make(map[string]bool)
	for i := 0; i < len(sources); i++ {
		sr := <-ch
		got := false
		for _, p := range sr.paths {
			p = strings.TrimPrefix(p, "/")
			if p == "" || seenPath[p] {
				continue
			}
			seenPath[p] = true
			res.Paths = append(res.Paths, p)
			got = true
		}
		for _, s := range sr.subs {
			if s == "" || seenSub[s] {
				continue
			}
			seenSub[s] = true
			res.Subdomains = append(res.Subdomains, s)
			got = true
		}
		if got {
			res.Sources = append(res.Sources, sr.name)
		}
	}
	return res
}

// wayback pulls unique historical URLs from the Internet Archive CDX API.
func (c *Collector) wayback(ctx context.Context, host string) ([]string, []string) {
	api := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=text&fl=original&collapse=urlkey&limit=%d",
		url.QueryEscape(host), c.MaxPerSource)
	body, err := c.get(ctx, api)
	if err != nil {
		return nil, nil
	}
	var paths []string
	for _, line := range strings.Split(body, "\n") {
		if p := pathOf(strings.TrimSpace(line), host); p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// otx pulls the URL list AlienVault OTX has observed for the host.
func (c *Collector) otx(ctx context.Context, host string) ([]string, []string) {
	api := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/hostname/%s/url_list?limit=500&page=1", url.PathEscape(host))
	body, err := c.get(ctx, api)
	if err != nil {
		return nil, nil
	}
	var parsed struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}
	if json.Unmarshal([]byte(body), &parsed) != nil {
		return nil, nil
	}
	var paths []string
	for _, e := range parsed.URLList {
		if p := pathOf(e.URL, host); p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// urlscan pulls page URLs urlscan.io has indexed for the domain.
func (c *Collector) urlscan(ctx context.Context, host string) ([]string, []string) {
	api := "https://urlscan.io/api/v1/search/?q=domain:" + url.QueryEscape(host) + "&size=1000"
	body, err := c.get(ctx, api)
	if err != nil {
		return nil, nil
	}
	var parsed struct {
		Results []struct {
			Page struct {
				URL    string `json:"url"`
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if json.Unmarshal([]byte(body), &parsed) != nil {
		return nil, nil
	}
	var paths, subs []string
	for _, r := range parsed.Results {
		if p := pathOf(r.Page.URL, host); p != "" {
			paths = append(paths, p)
		}
		if d := r.Page.Domain; d != "" && strings.HasSuffix(d, host) && d != host {
			subs = append(subs, d)
		}
	}
	return paths, subs
}

// crtsh pulls subdomains from Certificate Transparency logs via crt.sh.
func (c *Collector) crtsh(ctx context.Context, host string) ([]string, []string) {
	api := "https://crt.sh/?q=%25." + url.QueryEscape(host) + "&output=json"
	body, err := c.get(ctx, api)
	if err != nil {
		return nil, nil
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal([]byte(body), &entries) != nil {
		return nil, nil
	}
	seen := make(map[string]bool)
	var subs []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.TrimPrefix(name, "*."))
			if name == "" || name == host || seen[name] || !strings.HasSuffix(name, "."+host) {
				continue
			}
			seen[name] = true
			subs = append(subs, name)
		}
	}
	return nil, subs
}

// get performs a bounded GET and returns the response body as a string.
func (c *Collector) get(ctx context.Context, api string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", api, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "capsaicin-passive/1.0")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// pathOf returns the in-scope path (no leading slash) for a URL string whose host
// matches (or is a subdomain of) the target host; "" for out-of-scope or rootless
// URLs.
func pathOf(rawURL, host string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if h != host && !strings.HasSuffix(h, "."+host) {
		return ""
	}
	p := strings.TrimPrefix(u.Path, "/")
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}

// normalizeHost strips scheme, port, and path from a host/URL argument.
func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if h == "" {
		return ""
	}
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	return h
}
