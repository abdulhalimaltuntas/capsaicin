package smartfuzz

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Spider crawls a target's publicly accessible meta-files to extract seed words
// for intelligent fuzzing. It processes: homepage HTML, robots.txt, sitemap.xml,
// and JavaScript bundles.
type Spider struct {
	client  *http.Client
	timeout time.Duration
}

// NewSpider creates a spider with a configured HTTP client.
func NewSpider(timeout time.Duration) *Spider {
	return &Spider{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		timeout: timeout,
	}
}

// SeedResult holds all extracted words from a spider crawl.
type SeedResult struct {
	Paths    []string // Discovered paths (e.g., /api, /admin)
	Words    []string // Extracted keywords
	APIHints []string // Potential API patterns (e.g., v1, graphql)
}

// Crawl performs intelligence gathering on the target to extract seed words.
func (s *Spider) Crawl(ctx context.Context, targetURL string) (*SeedResult, error) {
	result := &SeedResult{}

	// 1. Parse robots.txt
	robotsPaths := s.parseRobots(ctx, targetURL)
	result.Paths = append(result.Paths, robotsPaths...)

	// 2. Parse sitemap.xml
	sitemapPaths := s.parseSitemap(ctx, targetURL)
	result.Paths = append(result.Paths, sitemapPaths...)

	// 3. Crawl homepage for paths and keywords
	homePaths, homeWords := s.parseHomepage(ctx, targetURL)
	result.Paths = append(result.Paths, homePaths...)
	result.Words = append(result.Words, homeWords...)

	// 4. Look for common JS bundles
	jsWords := s.parseJSBundles(ctx, targetURL)
	result.Words = append(result.Words, jsWords...)

	// Deduplicate all results.
	result.Paths = dedupStrings(result.Paths)
	result.Words = dedupStrings(result.Words)

	// Extract API hints from discovered paths.
	for _, p := range result.Paths {
		if isAPIHint(p) {
			result.APIHints = append(result.APIHints, p)
		}
	}

	return result, nil
}

func (s *Spider) fetch(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Capsaicin/3.0)")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB limit
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// parseRobots extracts Disallow and Allow paths from robots.txt.
var robotsPathRegex = regexp.MustCompile(`(?i)(?:Disallow|Allow):\s*(/[^\s*]*)`)

func (s *Spider) parseRobots(ctx context.Context, targetURL string) []string {
	body, err := s.fetch(ctx, strings.TrimSuffix(targetURL, "/")+"/robots.txt")
	if err != nil {
		return nil
	}

	matches := robotsPathRegex.FindAllStringSubmatch(body, -1)
	paths := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 && m[1] != "/" {
			paths = append(paths, strings.TrimSuffix(m[1], "/"))
		}
	}
	return paths
}

// parseSitemap extracts URL paths from sitemap.xml.
var sitemapLocRegex = regexp.MustCompile(`<loc>([^<]+)</loc>`)

func (s *Spider) parseSitemap(ctx context.Context, targetURL string) []string {
	body, err := s.fetch(ctx, strings.TrimSuffix(targetURL, "/")+"/sitemap.xml")
	if err != nil {
		return nil
	}

	matches := sitemapLocRegex.FindAllStringSubmatch(body, -1)
	paths := make([]string, 0, len(matches))
	baseHost := extractHost(targetURL)

	for _, m := range matches {
		if len(m) > 1 {
			loc := m[1]
			// Only extract paths from same-host URLs.
			if strings.Contains(loc, baseHost) {
				path := extractPathFromURL(loc)
				if path != "" && path != "/" {
					paths = append(paths, path)
				}
			}
		}
	}
	return paths
}

// parseHomepage extracts href paths and meta-keywords from the homepage.
var hrefRegex = regexp.MustCompile(`href=["']([^"'#?]+)["']`)
var srcRegex = regexp.MustCompile(`src=["']([^"'#?]+)["']`)

func (s *Spider) parseHomepage(ctx context.Context, targetURL string) ([]string, []string) {
	body, err := s.fetch(ctx, targetURL)
	if err != nil {
		return nil, nil
	}

	var paths []string
	var words []string

	// Extract href paths.
	for _, m := range hrefRegex.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			p := m[1]
			if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") {
				paths = append(paths, p)
			}
		}
	}

	// Extract src paths (for JS files).
	for _, m := range srcRegex.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			p := m[1]
			if strings.HasPrefix(p, "/") && strings.HasSuffix(p, ".js") {
				paths = append(paths, p)
			}
		}
	}

	// Extract words from visible text (crude but effective).
	wordRegex := regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9_-]{3,20}`)
	for _, w := range wordRegex.FindAllString(body, -1) {
		w = strings.ToLower(w)
		if !isCommonHTMLKeyword(w) {
			words = append(words, w)
		}
	}

	return paths, words
}

// parseJSBundles looks for common JS bundle files and extracts API route patterns.
var apiRouteRegex = regexp.MustCompile(`["'](/(?:api|v[0-9]+|graphql|rest|internal|admin|auth|oauth|users?|account)[^"']{0,60})["']`)

func (s *Spider) parseJSBundles(ctx context.Context, targetURL string) []string {
	// Try common bundle paths.
	bundlePaths := []string{
		"/static/js/main.js",
		"/static/js/app.js",
		"/assets/js/app.js",
		"/dist/bundle.js",
		"/build/static/js/main.js",
		"/js/app.js",
	}

	var words []string
	base := strings.TrimSuffix(targetURL, "/")

	for _, bp := range bundlePaths {
		body, err := s.fetch(ctx, base+bp)
		if err != nil {
			continue
		}

		// Extract API routes from JS source.
		for _, m := range apiRouteRegex.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				words = append(words, m[1])
			}
		}
	}

	return words
}

// Helpers

func extractHost(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	parts := strings.SplitN(u, "/", 2)
	return parts[0]
}

func extractPathFromURL(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	idx := strings.Index(u, "/")
	if idx < 0 {
		return "/"
	}
	return u[idx:]
}

func isAPIHint(path string) bool {
	lower := strings.ToLower(path)
	hints := []string{"api", "v1", "v2", "v3", "graphql", "rest", "admin", "internal", "oauth", "auth"}
	for _, h := range hints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

var commonHTMLKeywords = map[string]bool{
	"html": true, "head": true, "body": true, "div": true, "span": true,
	"class": true, "style": true, "script": true, "type": true, "text": true,
	"href": true, "link": true, "meta": true, "title": true, "content": true,
	"name": true, "charset": true, "http": true, "https": true, "function": true,
	"return": true, "const": true, "true": true, "false": true, "null": true,
	"undefined": true, "window": true, "document": true, "this": true,
}

func isCommonHTMLKeyword(w string) bool {
	return commonHTMLKeywords[w]
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
