package headless

import "testing"

func TestNeedsHeadlessCloudflare(t *testing.T) {
	body := `<html><head><title>Just a moment...</title></head><body>cf_chl_opt</body></html>`
	if !NeedsHeadless(body, "") {
		t.Error("Cloudflare Under Attack page should require headless")
	}
}

func TestNeedsHeadlessByWAFName(t *testing.T) {
	if !NeedsHeadless("plain body", "DataDome") {
		t.Error("DataDome WAF should require headless")
	}
}

func TestNeedsHeadlessNegative(t *testing.T) {
	if NeedsHeadless("<html><body>Normal admin page content</body></html>", "") {
		t.Error("ordinary page should not require headless")
	}
}

func TestIdentifyChallenge(t *testing.T) {
	tests := []struct {
		body string
		want ChallengeType
	}{
		{"cf-turnstile widget here", ChallengeCloudflare},
		{"please complete the g-recaptcha", ChallengeRecaptcha},
		{"blocked by datadome protection", ChallengeDataDome},
		{"some other challenge-form", ChallengeGeneric},
	}
	for _, tt := range tests {
		if got := IdentifyChallenge(tt.body); got != tt.want {
			t.Errorf("IdentifyChallenge(%q) = %v, want %v", tt.body, got, tt.want)
		}
	}
}
