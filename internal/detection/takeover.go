package detection

import "strings"

// TakeoverSignature identifies a dangling-resource takeover opportunity: a
// service whose "unclaimed resource" error page is being served for a host,
// meaning the host's DNS points at a de-provisioned resource an attacker can
// re-register.
type TakeoverSignature struct {
	Service      string   // human-readable provider name
	Fingerprints []string // body substrings that identify the provider's unclaimed page
}

// takeoverSignatures is a curated set of edge-service fingerprints. Kept
// conservative (each provider's canonical "no such site/bucket/app" text) to keep
// false positives near zero. Extend as new providers surface.
var takeoverSignatures = []TakeoverSignature{
	{"GitHub Pages", []string{"There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"}},
	{"Amazon S3", []string{"NoSuchBucket", "The specified bucket does not exist"}},
	{"Heroku", []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"}},
	{"Fastly", []string{"Fastly error: unknown domain", "Please check that this domain has been added to a service"}},
	{"Shopify", []string{"Sorry, this shop is currently unavailable", "Only one step left!"}},
	{"Zendesk", []string{"Help Center Closed", "this help center no longer exists"}},
	{"Bitbucket", []string{"Repository not found", "The page you have requested does not exist"}},
	{"Ghost", []string{"The thing you were looking for is no longer here, or never was"}},
	{"Pantheon", []string{"The gods are wise", "404 error unknown site"}},
	{"Tumblr", []string{"Whatever you were looking for doesn't currently exist at this address"}},
	{"WordPress.com", []string{"Do you want to register"}},
	{"Surge.sh", []string{"project not found"}},
	{"Cargo", []string{"If you're moving your domain away from Cargo"}},
	{"Netlify", []string{"Not Found - Request ID"}},
	{"Read the Docs", []string{"The requested host does not exist", "unknown to Read the Docs"}},
	{"Unbounce", []string{"The requested URL was not found on this server"}},
	{"Help Scout", []string{"No settings were found for this company"}},
	{"AWS/Elastic Beanstalk", []string{"404 Not Found", "elasticbeanstalk"}},
	{"Agile CRM", []string{"Sorry, this page is no longer available"}},
	{"Airee", []string{"Ошибка 402. Сервис Айри.рф не оплачен"}},
}

// DetectTakeover reports the provider whose unclaimed-resource page a body
// matches, or an empty string when none match. It is a fast substring scan over
// the response head, safe to run on 404/200/403 bodies.
func DetectTakeover(body string) string {
	if body == "" {
		return ""
	}
	head := body
	if len(head) > 8192 {
		head = head[:8192]
	}
	for _, sig := range takeoverSignatures {
		for _, fp := range sig.Fingerprints {
			if strings.Contains(head, fp) {
				return sig.Service
			}
		}
	}
	return ""
}
