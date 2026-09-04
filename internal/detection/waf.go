package detection

import (
	"net/http"
	"strings"
)

type WAFSignature struct {
	Name          string
	ServerHeader  string
	CustomHeader  string
	CookiePattern string
	BodyPattern   string
	StatusPattern int
}

var WAFSignatures = []WAFSignature{
	{
		Name:          "Cloudflare",
		ServerHeader:  "cloudflare",
		CookiePattern: "__cfduid",
	},
	{
		Name:         "AWS WAF",
		CustomHeader: "X-Amz-Cf-Id",
	},
	{
		Name:         "Akamai",
		ServerHeader: "AkamaiGHost",
	},
	{
		Name:         "Imperva",
		CustomHeader: "X-Iinfo",
	},
	{
		Name:          "F5 BigIP",
		CookiePattern: "BIGipServer",
	},
	{
		Name:         "Sucuri",
		ServerHeader: "Sucuri",
	},
	{
		Name:         "StackPath",
		ServerHeader: "StackPath",
	},
	{
		Name:         "Wordfence",
		CustomHeader: "X-Wf-",
	},
	{
		Name:         "Barracuda",
		ServerHeader: "Barracuda",
	},
	{
		Name:         "ModSecurity",
		ServerHeader: "Mod_Security",
	},
	{
		Name:          "Fortinet FortiWeb",
		CookiePattern: "FORTIWAFSID",
	},
	{
		Name:         "AWS Shield",
		CustomHeader: "X-Amzn-Trace-Id",
	},
	{
		Name:          "DenyAll",
		CookiePattern: "sessioncookie",
	},
	{
		Name:         "Cloudfront",
		CustomHeader: "X-Amz-Cf-Pop",
	},
	{
		Name:         "Fastly",
		CustomHeader: "X-Fastly-Request-ID",
	},
	{
		Name:         "Varnish",
		CustomHeader: "X-Varnish",
	},
	{
		Name:          "Incapsula",
		CookiePattern: "incap_ses",
		ServerHeader:  "Incapsula",
	},
	{
		Name:          "DataDome",
		ServerHeader:  "DataDome",
		CookiePattern: "datadome",
	},
}

func DetectWAF(resp *http.Response) string {
	for _, waf := range WAFSignatures {
		if waf.ServerHeader != "" {
			if server := resp.Header.Get("Server"); strings.Contains(strings.ToLower(server), strings.ToLower(waf.ServerHeader)) {
				return waf.Name
			}
		}

		if waf.CustomHeader != "" {
			for header := range resp.Header {
				if strings.Contains(strings.ToLower(header), strings.ToLower(waf.CustomHeader)) {
					return waf.Name
				}
			}
		}

		if waf.CookiePattern != "" {
			for _, cookie := range resp.Cookies() {
				if strings.Contains(cookie.Name, waf.CookiePattern) {
					return waf.Name
				}
			}
		}
	}

	return ""
}

func DetectWAFFromBody(body string, statusCode int) string {
	bodyPatterns := map[string]string{
		"Access Denied":                 "Generic WAF",
		"Request blocked":               "Generic WAF",
		"Sorry, you have been blocked":  "Cloudflare",
		"This request has been blocked": "Generic WAF",
		"Web Application Firewall":      "Generic WAF",
		"<title>Attention Required":     "Cloudflare",
		"<title>Just a moment":          "Cloudflare",
		"Powered by Wordfence":          "Wordfence",
		"ModSecurity":                   "ModSecurity",
		"<title>403 Forbidden</title>":  "Generic WAF",
		"cf-turnstile":                  "Cloudflare Turnstile",
		"g-recaptcha":                   "reCAPTCHA",
		"datadome":                      "DataDome",
		"incapsula incident id":         "Incapsula",
	}

	lowerBody := strings.ToLower(body)
	for pattern, wafName := range bodyPatterns {
		if strings.Contains(lowerBody, strings.ToLower(pattern)) {
			return wafName
		}
	}

	return ""
}
