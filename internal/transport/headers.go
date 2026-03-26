package transport

import (
	"math/rand"
	"net/http"
	"strings"
)

// BrowserProfile defines a strict, coherent set of HTTP headers corresponding
// to a specific real-world browser and OS version. This prevents WAFs from
// detecting anomalies like a Chrome User-Agent with Firefox headers.
type BrowserProfile struct {
	UserAgent      string
	Accept         string
	AcceptLanguage string
	SecChUa        string
	SecChUaMobile  string
	SecChPlatform  string
	SecFetchDest   string
	SecFetchMode   string
	SecFetchSite   string
	SecFetchUser   string
}

// predefinedProfiles provides hardcoded, coherent header sets.
var predefinedProfiles = map[string][]BrowserProfile{
	"chrome": {
		{
			UserAgent:      `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`,
			Accept:         `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`,
			AcceptLanguage: `en-US,en;q=0.9`,
			SecChUa:        `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			SecChUaMobile:  `?0`,
			SecChPlatform:  `"Windows"`,
			SecFetchDest:   `document`,
			SecFetchMode:   `navigate`,
			SecFetchSite:   `none`,
			SecFetchUser:   `?1`,
		},
		{
			UserAgent:      `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36`,
			Accept:         `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8`,
			AcceptLanguage: `en-GB,en-US;q=0.9,en;q=0.8`,
			SecChUa:        `"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"`,
			SecChUaMobile:  `?0`,
			SecChPlatform:  `"macOS"`,
			SecFetchDest:   `document`,
			SecFetchMode:   `navigate`,
			SecFetchSite:   `same-origin`,
			SecFetchUser:   `?1`,
		},
	},
	"firefox": {
		{
			UserAgent:      `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0`,
			Accept:         `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8`,
			AcceptLanguage: `en-US,en;q=0.5`,
			SecChUa:        ``, // Firefox does not send Sec-CH headers
			SecChUaMobile:  ``,
			SecChPlatform:  ``,
			SecFetchDest:   `document`,
			SecFetchMode:   `navigate`,
			SecFetchSite:   `cross-site`,
			SecFetchUser:   `?1`,
		},
	},
	"safari": {
		{
			UserAgent:      `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15`,
			Accept:         `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`,
			AcceptLanguage: `en-US,en;q=0.9`,
			SecChUa:        ``, // Safari historically does not send Sec-CH
			SecChUaMobile:  ``,
			SecChPlatform:  ``,
			SecFetchDest:   `document`,
			SecFetchMode:   `navigate`,
			SecFetchSite:   `none`,
			SecFetchUser:   `?1`,
		},
	},
}

// GetCoherentProfile selects a random, strict browser profile based on the requested family.
func GetCoherentProfile(family string, rng *rand.Rand) *BrowserProfile {
	family = strings.ToLower(family)
	if family == "random" {
		families := []string{"chrome", "firefox", "safari"}
		family = families[rng.Intn(len(families))]
	}

	profiles, ok := predefinedProfiles[family]
	if !ok || len(profiles) == 0 {
		profiles = predefinedProfiles["chrome"]
	}

	return &profiles[rng.Intn(len(profiles))]
}

// ApplyProfile injects the coherent headers into the request. Existing headers
// (e.g., from -H flag) take precedence and will not be overwritten.
func ApplyProfile(req *http.Request, profile *BrowserProfile) {
	setIfEmpty := func(key, value string) {
		if value != "" && req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}

	if req.UserAgent() == "" && profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	setIfEmpty("Accept", profile.Accept)
	setIfEmpty("Accept-Language", profile.AcceptLanguage)
	setIfEmpty("Sec-CH-UA", profile.SecChUa)
	setIfEmpty("Sec-CH-UA-Mobile", profile.SecChUaMobile)
	setIfEmpty("Sec-CH-UA-Platform", profile.SecChPlatform)
	setIfEmpty("Sec-Fetch-Dest", profile.SecFetchDest)
	setIfEmpty("Sec-Fetch-Mode", profile.SecFetchMode)
	setIfEmpty("Sec-Fetch-Site", profile.SecFetchSite)
	setIfEmpty("Sec-Fetch-User", profile.SecFetchUser)
}
