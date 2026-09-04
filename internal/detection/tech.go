package detection

import (
	"net/http"
	"strings"
)

// TechFingerprint infers backend/framework technology tags from response
// headers. Tags are used for reporting context and to bias future wordlist
// selection (e.g. a PHP stack warrants .php probing).
//
// It is intentionally header-driven (cheap, no body parsing) and conservative:
// it only emits a tag when a header value clearly implies it.
func TechFingerprint(resp *http.Response) []string {
	if resp == nil {
		return nil
	}
	seen := make(map[string]bool)
	var tags []string
	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		tags = append(tags, t)
	}

	server := strings.ToLower(resp.Header.Get("Server"))
	powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
	combined := server + " " + powered

	for needle, tag := range headerTechMap {
		if strings.Contains(combined, needle) {
			add(tag)
		}
	}

	// Framework-specific headers.
	if resp.Header.Get("X-AspNet-Version") != "" || resp.Header.Get("X-AspNetMvc-Version") != "" {
		add("ASP.NET")
	}
	if resp.Header.Get("X-Drupal-Cache") != "" || resp.Header.Get("X-Generator") != "" {
		if strings.Contains(strings.ToLower(resp.Header.Get("X-Generator")), "drupal") {
			add("Drupal")
		}
	}
	if _, ok := resp.Header["X-Shopify-Stage"]; ok {
		add("Shopify")
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Set-Cookie")), "laravel_session") {
		add("Laravel")
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Set-Cookie")), "wordpress_") {
		add("WordPress")
	}

	return tags
}

// headerTechMap maps a lowercase substring of Server/X-Powered-By to a tag.
var headerTechMap = map[string]string{
	"nginx":      "nginx",
	"apache":     "Apache",
	"iis":        "IIS",
	"microsoft-": "IIS",
	"litespeed":  "LiteSpeed",
	"caddy":      "Caddy",
	"php":        "PHP",
	"express":    "Express",
	"node":       "Node.js",
	"asp.net":    "ASP.NET",
	"tomcat":     "Tomcat",
	"jetty":      "Jetty",
	"gunicorn":   "Gunicorn/Python",
	"werkzeug":   "Flask/Python",
	"django":     "Django",
	"phusion":    "Passenger/Ruby",
	"puma":       "Puma/Ruby",
	"kestrel":    "Kestrel/.NET",
	"cowboy":     "Cowboy/Erlang",
	"openresty":  "OpenResty",
	"cloudflare": "Cloudflare",
	"vercel":     "Vercel",
	"netlify":    "Netlify",
	"gws":        "Google",
	"nextjs":     "Next.js",
	"wordpress":  "WordPress",
}

// SuggestExtensions returns file extensions worth probing for a given set of
// technology tags, so a dynamic scan can adapt its extension list to the stack.
func SuggestExtensions(tags []string) []string {
	seen := make(map[string]bool)
	var exts []string
	add := func(e string) {
		if !seen[e] {
			seen[e] = true
			exts = append(exts, e)
		}
	}
	for _, t := range tags {
		switch t {
		case "PHP", "WordPress", "Laravel", "Drupal":
			add(".php")
		case "ASP.NET", "IIS", "Kestrel/.NET":
			add(".aspx")
			add(".asp")
		case "Django", "Flask/Python", "Gunicorn/Python":
			add(".py")
		case "Express", "Node.js", "Next.js":
			add(".js")
		case "Tomcat", "Jetty":
			add(".jsp")
		}
	}
	return exts
}
