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