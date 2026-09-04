package detection

import (
	"fmt"
	"testing"
)

func TestSimHashIdenticalBodies(t *testing.T) {
	body := "the quick brown fox jumps over the lazy dog many times over"
	h1 := SimHash(body)
	h2 := SimHash(body)
	if h1 != h2 {
		t.Fatal("SimHash is not deterministic for identical input")
	}
}

func TestSimHashNearDuplicateSoft404(t *testing.T) {
	// Two soft-404 pages that only differ by the echoed path should be near
	// duplicates (small Hamming distance).
	tmpl := "<html><body><h1>Not Found</h1><p>The page %s could not be located on this server.</p></body></html>"
	a := SimHash(fmt.Sprintf(tmpl, "/admin"))
	b := SimHash(fmt.Sprintf(tmpl, "/backup"))

	if d := HammingDistance(a, b); d > simHashThreshold {
		t.Errorf("near-duplicate soft-404 bodies should be within threshold, distance=%d", d)
	}
}

func TestSimHashDistinctPages(t *testing.T) {
	a := SimHash("<html><body>Welcome to the admin dashboard with user management and billing</body></html>")
	b := SimHash("<html><body>404 page not found error the requested resource does not exist</body></html>")

	if d := HammingDistance(a, b); d <= simHashThreshold {
		t.Errorf("distinct pages should exceed threshold, distance=%d", d)
	}
}

func TestSimHashEmpty(t *testing.T) {
	if SimHash("") != 0 {
		t.Error("empty body should hash to 0")
	}
}

func TestMatchesBaselineBodySoft404(t *testing.T) {
	// Realistic soft-404: a substantial template whose only per-request
	// variation is the single echoed path token.
	boilerplate := "Our application server could not find the resource you requested. " +
		"Please check the address bar for typos or return to the homepage to continue " +
		"browsing our catalog of products services documentation support and account " +
		"management pages. If you believe this is an error contact our support team with " +
		"the reference identifier shown below and a description of what you were doing."
	tmpl := func(p string) string {
		return "<html><head><title>Page Not Found</title></head><body><h1>404</h1><p>" +
			boilerplate + " Requested path: " + p + "</p></body></html>"
	}
	probes := []ResponseSignature{
		{StatusCode: 404, Size: 470, WordCount: 62, LineCount: 1, SimHash: SimHash(tmpl("alpha"))},
		{StatusCode: 404, Size: 472, WordCount: 62, LineCount: 1, SimHash: SimHash(tmpl("bravo"))},
		{StatusCode: 404, Size: 468, WordCount: 62, LineCount: 1, SimHash: SimHash(tmpl("charlie"))},
	}
	baseline := buildBaseline(probes)

	// A real request whose size lands outside tolerant ranges but whose body is
	// the same soft-404 template must still be filtered as noise.
	realBody := tmpl("adminpanel")
	if !MatchesBaselineBody(404, 900, 62, 1, SimHash(realBody), baseline) {
		t.Error("soft-404 near-duplicate should be filtered via SimHash fallback")
	}

	// A genuinely different 200 page must NOT be filtered.
	realPage := SimHash("<html><body>Admin dashboard: users, roles, billing, invoices, settings</body></html>")
	if MatchesBaselineBody(200, 500, 40, 3, realPage, baseline) {
		t.Error("distinct 200 page should not be filtered")
	}
}
