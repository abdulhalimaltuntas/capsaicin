package detection

import (
	"net/http"
	"strings"
)

// TechCategory groups related technologies for cleaner reporting.
type TechCategory string

const (
	CategoryWebServer TechCategory = "web-server"
	CategoryLanguage  TechCategory = "language"
	CategoryFramework TechCategory = "framework"
	CategoryCMS       TechCategory = "cms"
	CategoryJSLib     TechCategory = "js-library"
	CategoryCDN       TechCategory = "cdn"
	CategoryOther     TechCategory = "other"
)

// TechSignature defines a fingerprint for a single technology.
// Detection runs through four layers in order:
// header → cookie → meta tag → body pattern.
type TechSignature struct {
	Name         string
	Category     TechCategory
	HeaderName   string // response header key to inspect (case-insensitive)
	HeaderValue  string // substring match against the header value
	CookieName   string // cookie name substring match
	MetaTag      string // <meta name="generator" content="..."> substring match
	BodyPattern  string // raw body substring match
}

// TechMatch holds the result of a single technology detection.
type TechMatch struct {
	Name     string       `json:"name"`
	Category TechCategory `json:"category"`
}

// techSignatures is the master list of fingerprints. Ordered roughly by
// how common each tech is in the wild. Keep it lean; we're not trying to
// replicate Wappalyzer — just catch the obvious stuff during a scan.
var techSignatures = []TechSignature{
	// ── Web Servers ────────────────────────────────────────────
	{Name: "Nginx", Category: CategoryWebServer, HeaderName: "Server", HeaderValue: "nginx"},
	{Name: "Apache", Category: CategoryWebServer, HeaderName: "Server", HeaderValue: "apache"},
	{Name: "IIS", Category: CategoryWebServer, HeaderName: "Server", HeaderValue: "microsoft-iis"},
	{Name: "LiteSpeed", Category: CategoryWebServer, HeaderName: "Server", HeaderValue: "litespeed"},
	{Name: "Caddy", Category: CategoryWebServer, HeaderName: "Server", HeaderValue: "caddy"},
	{Name: "Openresty", Category: CategoryWebServer, HeaderName: "Server", HeaderValue: "openresty"},
	{Name: "Gunicorn", Category: CategoryWebServer, HeaderName: "Server", HeaderValue: "gunicorn"},
	{Name: "Cowboy", Category: CategoryWebServer, HeaderName: "Server", HeaderValue: "cowboy"},

	// ── Languages / Runtimes ──────────────────────────────────
	{Name: "PHP", Category: CategoryLanguage, HeaderName: "X-Powered-By", HeaderValue: "php"},
	{Name: "PHP", Category: CategoryLanguage, CookieName: "PHPSESSID"},
	{Name: "ASP.NET", Category: CategoryLanguage, HeaderName: "X-Powered-By", HeaderValue: "asp.net"},
	{Name: "ASP.NET", Category: CategoryLanguage, HeaderName: "X-AspNet-Version", HeaderValue: ""},
	{Name: "ASP.NET", Category: CategoryLanguage, CookieName: "ASP.NET_SessionId"},
	{Name: "Java", Category: CategoryLanguage, CookieName: "JSESSIONID"},
	{Name: "Express", Category: CategoryFramework, HeaderName: "X-Powered-By", HeaderValue: "express"},
	{Name: "Python", Category: CategoryLanguage, HeaderName: "X-Powered-By", HeaderValue: "python"},
	{Name: "Django", Category: CategoryFramework, CookieName: "csrftoken"},
	{Name: "Django", Category: CategoryFramework, CookieName: "django_language"},
	{Name: "Rails", Category: CategoryFramework, HeaderName: "X-Powered-By", HeaderValue: "phusion passenger"},
	{Name: "Rails", Category: CategoryFramework, CookieName: "_rails_session"},

	// ── CMS ───────────────────────────────────────────────────
	{Name: "WordPress", Category: CategoryCMS, MetaTag: "wordpress"},
	{Name: "WordPress", Category: CategoryCMS, BodyPattern: "wp-content"},
	{Name: "WordPress", Category: CategoryCMS, BodyPattern: "wp-includes"},
	{Name: "Joomla", Category: CategoryCMS, MetaTag: "joomla"},
	{Name: "Joomla", Category: CategoryCMS, BodyPattern: "/media/jui/"},
	{Name: "Drupal", Category: CategoryCMS, MetaTag: "drupal"},
	{Name: "Drupal", Category: CategoryCMS, HeaderName: "X-Generator", HeaderValue: "drupal"},
	{Name: "Drupal", Category: CategoryCMS, BodyPattern: "sites/default/files"},
	{Name: "Shopify", Category: CategoryCMS, BodyPattern: "cdn.shopify.com"},

	// ── JS Frameworks / Libraries ─────────────────────────────
	{Name: "React", Category: CategoryJSLib, BodyPattern: "__NEXT_DATA__"},
	{Name: "React", Category: CategoryJSLib, BodyPattern: "data-reactroot"},
	{Name: "Next.js", Category: CategoryFramework, HeaderName: "X-Powered-By", HeaderValue: "next.js"},
	{Name: "Next.js", Category: CategoryFramework, BodyPattern: "_next/static"},
	{Name: "Nuxt.js", Category: CategoryFramework, BodyPattern: "__nuxt"},
	{Name: "Vue.js", Category: CategoryJSLib, BodyPattern: "data-v-"},
	{Name: "Angular", Category: CategoryJSLib, BodyPattern: "ng-version="},
	{Name: "jQuery", Category: CategoryJSLib, BodyPattern: "jquery.min.js"},
	{Name: "jQuery", Category: CategoryJSLib, BodyPattern: "jquery/"},

	// ── CDN / Hosting ─────────────────────────────────────────
	{Name: "AWS S3", Category: CategoryCDN, HeaderName: "Server", HeaderValue: "amazons3"},
	{Name: "Heroku", Category: CategoryCDN, HeaderName: "Via", HeaderValue: "heroku"},
	{Name: "Vercel", Category: CategoryCDN, HeaderName: "X-Vercel-Id", HeaderValue: ""},
	{Name: "Netlify", Category: CategoryCDN, HeaderName: "X-Nf-Request-Id", HeaderValue: ""},
	{Name: "Firebase", Category: CategoryCDN, HeaderName: "X-Served-By", HeaderValue: "firebase"},

	// ── Other ─────────────────────────────────────────────────
	{Name: "OpenSSL", Category: CategoryOther, HeaderName: "Server", HeaderValue: "openssl"},
	{Name: "Laravel", Category: CategoryFramework, CookieName: "laravel_session"},
	{Name: "Laravel", Category: CategoryFramework, CookieName: "XSRF-TOKEN"},
	{Name: "Spring", Category: CategoryFramework, CookieName: "JSESSIONID"},
	{Name: "Flask", Category: CategoryFramework, HeaderName: "Server", HeaderValue: "werkzeug"},
}

// DetectTechnologies inspects an HTTP response (headers + cookies) and the
// response body looking for known technology fingerprints. It returns a
// deduplicated list of matches.
func DetectTechnologies(resp *http.Response, body string) []TechMatch {
	if resp == nil {
		return nil
	}

	seen := make(map[string]bool)
	var matches []TechMatch

	lowerBody := strings.ToLower(body)

	for _, sig := range techSignatures {
		if seen[sig.Name] {
			continue
		}

		if matchesTechSignature(resp, lowerBody, &sig) {
			seen[sig.Name] = true
			matches = append(matches, TechMatch{
				Name:     sig.Name,
				Category: sig.Category,
			})
		}
	}

	return matches
}

// DetectTechNames is a convenience wrapper that returns just the tech names.
func DetectTechNames(resp *http.Response, body string) []string {
	matches := DetectTechnologies(resp, body)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.Name)
	}
	return names
}

// matchesTechSignature checks a single signature against the response.
func matchesTechSignature(resp *http.Response, lowerBody string, sig *TechSignature) bool {
	// Header match
	if sig.HeaderName != "" {
		headerVal := resp.Header.Get(sig.HeaderName)
		if headerVal != "" {
			// If no specific value required, just header presence is enough.
			if sig.HeaderValue == "" {
				return true
			}
			if strings.Contains(strings.ToLower(headerVal), sig.HeaderValue) {
				return true
			}
		}
	}

	// Cookie match
	if sig.CookieName != "" {
		for _, cookie := range resp.Cookies() {
			if strings.Contains(cookie.Name, sig.CookieName) {
				return true
			}
		}
	}

	// Meta tag match — look for <meta name="generator" content="...">
	if sig.MetaTag != "" {
		// We check a simplified pattern; good enough for fingerprinting.
		if strings.Contains(lowerBody, sig.MetaTag) &&
			strings.Contains(lowerBody, "generator") {
			return true
		}
	}

	// Body pattern match
	if sig.BodyPattern != "" {
		if strings.Contains(lowerBody, strings.ToLower(sig.BodyPattern)) {
			return true
		}
	}

	return false
}
