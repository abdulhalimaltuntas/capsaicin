package detection

import (
	"regexp"
	"strconv"
	"strings"
)

// CVE is a matched vulnerability: identifier plus its severity and a one-line
// description, so the caller can both tag and score the finding.
type CVE struct {
	ID          string
	Severity    string // critical|high|medium
	Description string
}

// cveEntry is one product/version-range → CVE mapping. A version v matches when
// introduced <= v <= lastAffected (either bound empty means unbounded on that
// side). Kept as a small, curated, high-signal table of remotely-fingerprintable
// server CVEs — not a full NVD mirror. Extend as needed.
type cveEntry struct {
	product      string // lowercase product token as it appears in Server/X-Powered-By
	introduced   string // first affected version (inclusive); "" = any earlier
	lastAffected string // last affected version (inclusive); "" = any later
	cve          CVE
}

var cveTable = []cveEntry{
	{"apache", "2.4.49", "2.4.49", CVE{"CVE-2021-41773", "critical", "path traversal + RCE"}},
	{"apache", "2.4.50", "2.4.50", CVE{"CVE-2021-42013", "critical", "path traversal + RCE (incomplete 41773 fix)"}},
	{"apache", "2.4.0", "2.4.48", CVE{"CVE-2021-40438", "high", "mod_proxy SSRF"}},
	{"nginx", "0.5.6", "1.13.2", CVE{"CVE-2017-7529", "high", "range filter integer overflow"}},
	{"nginx", "1.3.9", "1.5.6", CVE{"CVE-2013-2028", "high", "chunked transfer stack overflow"}},
	{"openssh", "1.0", "8.7", CVE{"CVE-2021-41617", "medium", "privsep child privilege escalation"}},
	{"openssh", "6.2", "8.7", CVE{"CVE-2021-28041", "medium", "ssh-agent double free"}},
	{"php", "7.0.0", "7.4.32", CVE{"CVE-2019-11043", "critical", "php-fpm underflow RCE (env_path_info)"}},
	{"iis", "7.0", "7.5", CVE{"CVE-2015-1635", "critical", "HTTP.sys remote code execution (MS15-034)"}},
	{"tomcat", "9.0.0", "9.0.30", CVE{"CVE-2020-1938", "critical", "Ghostcat AJP file read/inclusion"}},
	{"tomcat", "7.0.0", "7.0.99", CVE{"CVE-2020-1938", "critical", "Ghostcat AJP file read/inclusion"}},
	{"jetty", "9.4.37", "9.4.42", CVE{"CVE-2021-34429", "high", "URI-encoded WEB-INF disclosure"}},
	{"lighttpd", "1.4.0", "1.4.50", CVE{"CVE-2019-11072", "high", "mod_cml use-after-free"}},
	{"openresty", "1.0", "1.15.8.3", CVE{"CVE-2020-11724", "medium", "ngx_http_lua header injection"}},
}

// serverVersionRe captures a product token and dotted version from a Server or
// X-Powered-By header value, e.g. "nginx/1.18.0", "Apache/2.4.49 (Unix)".
var serverVersionRe = regexp.MustCompile(`(?i)([a-zA-Z][a-zA-Z0-9_+-]*)/(\d+(?:\.\d+){0,3})`)

// CVEsForServer parses product/version pairs out of a Server-style header and
// returns matching CVEs. Multiple products in one header (e.g. "Apache/2.4.49
// PHP/7.4.0") are each checked.
func CVEsForServer(headerValue string) []CVE {
	if headerValue == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []CVE
	for _, m := range serverVersionRe.FindAllStringSubmatch(headerValue, -1) {
		if len(m) < 3 {
			continue
		}
		product := strings.ToLower(m[1])
		version := m[2]
		for i := range cveTable {
			e := &cveTable[i]
			if e.product != product {
				continue
			}
			if !versionInRange(version, e.introduced, e.lastAffected) {
				continue
			}
			if !seen[e.cve.ID] {
				seen[e.cve.ID] = true
				out = append(out, e.cve)
			}
		}
	}
	return out
}

// versionInRange reports whether v is within [lo, hi] inclusive. Empty lo/hi are
// treated as unbounded.
func versionInRange(v, lo, hi string) bool {
	if lo != "" && compareVersions(v, lo) < 0 {
		return false
	}
	if hi != "" && compareVersions(v, hi) > 0 {
		return false
	}
	return true
}

// compareVersions compares two dotted numeric versions. Returns -1, 0, or +1.
// Missing trailing components are treated as zero (1.2 == 1.2.0).
func compareVersions(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var xa, xb int
		if i < len(pa) {
			xa, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			xb, _ = strconv.Atoi(pb[i])
		}
		if xa != xb {
			if xa < xb {
				return -1
			}
			return 1
		}
	}
	return 0
}
