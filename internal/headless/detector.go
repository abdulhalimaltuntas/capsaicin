package headless

import "strings"

// JSChallengePatterns defines body content patterns that indicate a JavaScript
// challenge page which cannot be solved with raw HTTP — a headless browser is required.
var JSChallengePatterns = []string{
	"<title>just a moment</title>",       // Cloudflare Under Attack Mode
	"<title>attention required</title>",   // Cloudflare captcha gate
	"cf-turnstile",                        // Cloudflare Turnstile widget
	"cf_chl_opt",                          // Cloudflare challenge options JS var
	"g-recaptcha",                         // Google reCAPTCHA v2/v3
	"grecaptcha.execute",                  // reCAPTCHA v3 programmatic
	"datadome",                            // DataDome anti-bot
	"dd.js",                               // DataDome loader script
	"cdn-cgi/challenge-platform",          // Cloudflare challenge platform
	"_cf_chl_managed_tk",                  // Cloudflare managed challenge token
	"interstitialUrl",                     // Generic interstitial redirect
	"managed_checking_msg",               // Cloudflare "checking your browser"
	"challenge-form",                      // Generic challenge form ID
	"browser-verification",               // Generic browser verification
}

// NeedsHeadless inspects an HTTP response body and WAF detection result to
// determine if a headless browser is required to solve a JS challenge and
// extract valid session cookies.
func NeedsHeadless(bodyContent string, wafName string) bool {
	lower := strings.ToLower(bodyContent)
	for _, pattern := range JSChallengePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Known WAFs that frequently use JS challenges.
	switch wafName {
	case "Cloudflare Turnstile", "reCAPTCHA", "DataDome":
		return true
	}

	return false
}

// ChallengeType identifies what kind of JS challenge was detected.
type ChallengeType int

const (
	ChallengeUnknown ChallengeType = iota
	ChallengeCloudflare
	ChallengeRecaptcha
	ChallengeDataDome
	ChallengeGeneric
)

// IdentifyChallenge returns the specific challenge type for targeted solving.
func IdentifyChallenge(bodyContent string) ChallengeType {
	lower := strings.ToLower(bodyContent)

	switch {
	case strings.Contains(lower, "cf-turnstile") || strings.Contains(lower, "cf_chl_opt") ||
		strings.Contains(lower, "cdn-cgi/challenge-platform"):
		return ChallengeCloudflare
	case strings.Contains(lower, "g-recaptcha") || strings.Contains(lower, "grecaptcha"):
		return ChallengeRecaptcha
	case strings.Contains(lower, "datadome") || strings.Contains(lower, "dd.js"):
		return ChallengeDataDome
	default:
		return ChallengeGeneric
	}
}
