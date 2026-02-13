package detection

import (
	"net/http"
	"testing"
)

func buildResponse(headers map[string]string, cookies []*http.Cookie) *http.Response {
	resp := &http.Response{
		Header: make(http.Header),
	}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	for _, c := range cookies {
		resp.Header.Add("Set-Cookie", c.String())
	}
	return resp
}

func TestDetectTechnologies_Headers(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{"Nginx via Server header", map[string]string{"Server": "nginx/1.24.0"}, "Nginx"},
		{"Apache via Server header", map[string]string{"Server": "Apache/2.4.52 (Ubuntu)"}, "Apache"},
		{"IIS via Server header", map[string]string{"Server": "Microsoft-IIS/10.0"}, "IIS"},
		{"LiteSpeed via Server header", map[string]string{"Server": "LiteSpeed"}, "LiteSpeed"},
		{"PHP via X-Powered-By", map[string]string{"X-Powered-By": "PHP/8.2.0"}, "PHP"},
		{"ASP.NET via X-Powered-By", map[string]string{"X-Powered-By": "ASP.NET"}, "ASP.NET"},
		{"Express via X-Powered-By", map[string]string{"X-Powered-By": "Express"}, "Express"},
		{"Next.js via X-Powered-By", map[string]string{"X-Powered-By": "Next.js"}, "Next.js"},
		{"ASP.NET via version header", map[string]string{"X-AspNet-Version": "4.0.30319"}, "ASP.NET"},
		{"Drupal via X-Generator", map[string]string{"X-Generator": "Drupal 10"}, "Drupal"},
		{"Vercel via X-Vercel-Id", map[string]string{"X-Vercel-Id": "iad1::abc123"}, "Vercel"},
		{"Netlify via X-Nf-Request-Id", map[string]string{"X-Nf-Request-Id": "01abc"}, "Netlify"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := buildResponse(tt.headers, nil)
			matches := DetectTechnologies(resp, "")

			found := false
			for _, m := range matches {
				if m.Name == tt.expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected to detect %q, got %v", tt.expected, matches)
			}
		})
	}
}

func TestDetectTechnologies_Cookies(t *testing.T) {
	tests := []struct {
		name     string
		cookies  []*http.Cookie
		expected string
	}{
		{
			"PHP via PHPSESSID",
			[]*http.Cookie{{Name: "PHPSESSID", Value: "abc123"}},
			"PHP",
		},
		{
			"Java via JSESSIONID",
			[]*http.Cookie{{Name: "JSESSIONID", Value: "xyz789"}},
			"Java",
		},
		{
			"ASP.NET via session cookie",
			[]*http.Cookie{{Name: "ASP.NET_SessionId", Value: "def456"}},
			"ASP.NET",
		},
		{
			"Django via csrftoken",
			[]*http.Cookie{{Name: "csrftoken", Value: "tok123"}},
			"Django",
		},
		{
			"Laravel via laravel_session",
			[]*http.Cookie{{Name: "laravel_session", Value: "sess456"}},
			"Laravel",
		},
		{
			"Rails via _rails_session",
			[]*http.Cookie{{Name: "_rails_session", Value: "rail789"}},
			"Rails",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := buildResponse(nil, tt.cookies)
			matches := DetectTechnologies(resp, "")

			found := false
			for _, m := range matches {
				if m.Name == tt.expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected to detect %q, got %v", tt.expected, matches)
			}
		})
	}
}

func TestDetectTechnologies_Body(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			"WordPress via wp-content",
			`<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">`,
			"WordPress",
		},
		{
			"React via data-reactroot",
			`<div id="root" data-reactroot="">Hello</div>`,
			"React",
		},
		{
			"Angular via ng-version",
			`<app-root ng-version="17.0.0"></app-root>`,
			"Angular",
		},
		{
			"Vue.js via data-v-",
			`<div data-v-7ba5bd90 class="container">Content</div>`,
			"Vue.js",
		},
		{
			"Next.js via _next/static",
			`<script src="/_next/static/chunks/main.js"></script>`,
			"Next.js",
		},
		{
			"jQuery via jquery.min.js",
			`<script src="/js/jquery.min.js"></script>`,
			"jQuery",
		},
		{
			"Shopify via cdn.shopify.com",
			`<link rel="stylesheet" href="https://cdn.shopify.com/s/files/1/theme.css">`,
			"Shopify",
		},
		{
			"Nuxt.js via __nuxt",
			`<div id="__nuxt"><div id="__layout">Content</div></div>`,
			"Nuxt.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := buildResponse(nil, nil)
			matches := DetectTechnologies(resp, tt.body)

			found := false
			for _, m := range matches {
				if m.Name == tt.expected {
					found = true
					break
				}
			}
			if !found {
				names := DetectTechNames(resp, tt.body)
				t.Errorf("expected to detect %q, got %v", tt.expected, names)
			}
		})
	}
}

func TestDetectTechnologies_MetaGenerator(t *testing.T) {
	body := `<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>`
	resp := buildResponse(nil, nil)
	matches := DetectTechnologies(resp, body)

	found := false
	for _, m := range matches {
		if m.Name == "WordPress" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to detect WordPress via meta generator tag")
	}
}

func TestDetectTechnologies_Multiple(t *testing.T) {
	headers := map[string]string{
		"Server":       "nginx/1.24.0",
		"X-Powered-By": "PHP/8.2.0",
	}
	body := `<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">
	<script src="/js/jquery.min.js"></script>`

	resp := buildResponse(headers, nil)
	matches := DetectTechnologies(resp, body)

	expected := map[string]bool{"Nginx": false, "PHP": false, "WordPress": false, "jQuery": false}
	for _, m := range matches {
		if _, ok := expected[m.Name]; ok {
			expected[m.Name] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("expected to detect %q in multi-tech response", name)
		}
	}
}

func TestDetectTechnologies_NoDuplicates(t *testing.T) {
	// WordPress can match via both wp-content and wp-includes patterns
	body := `<link href="/wp-content/style.css"><script src="/wp-includes/js/main.js">`
	resp := buildResponse(nil, nil)
	matches := DetectTechnologies(resp, body)

	wpCount := 0
	for _, m := range matches {
		if m.Name == "WordPress" {
			wpCount++
		}
	}

	if wpCount > 1 {
		t.Errorf("expected WordPress to appear once, got %d times", wpCount)
	}
}

func TestDetectTechnologies_Empty(t *testing.T) {
	resp := buildResponse(nil, nil)
	matches := DetectTechnologies(resp, "")

	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty response, got %d: %v", len(matches), matches)
	}
}

func TestDetectTechnologies_NilResponse(t *testing.T) {
	matches := DetectTechnologies(nil, "some body content")
	if matches != nil {
		t.Errorf("expected nil for nil response, got %v", matches)
	}
}

func TestDetectTechNames(t *testing.T) {
	headers := map[string]string{"Server": "nginx/1.24.0"}
	resp := buildResponse(headers, nil)
	names := DetectTechNames(resp, "")

	if len(names) == 0 {
		t.Fatal("expected at least one tech name")
	}
	if names[0] != "Nginx" {
		t.Errorf("expected first name to be Nginx, got %q", names[0])
	}
}

func TestDetectTechnologies_Categories(t *testing.T) {
	headers := map[string]string{"Server": "nginx/1.24.0", "X-Powered-By": "Express"}
	resp := buildResponse(headers, nil)
	matches := DetectTechnologies(resp, "")

	for _, m := range matches {
		if m.Name == "Nginx" && m.Category != CategoryWebServer {
			t.Errorf("expected Nginx to have web-server category, got %q", m.Category)
		}
		if m.Name == "Express" && m.Category != CategoryFramework {
			t.Errorf("expected Express to have framework category, got %q", m.Category)
		}
	}
}

func TestDetectTechnologies_CaseInsensitive(t *testing.T) {
	// Server header values should match case-insensitively
	headers := map[string]string{"Server": "NGINX/1.24.0"}
	resp := buildResponse(headers, nil)
	matches := DetectTechnologies(resp, "")

	found := false
	for _, m := range matches {
		if m.Name == "Nginx" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Nginx detection to be case-insensitive")
	}
}
