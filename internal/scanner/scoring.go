package scanner

import "strings"

// Severity constants for risk classification.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Confidence constants indicating evidence strength.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceFirm      = "firm"
	ConfidenceTentative = "tentative"
)

// severityRank maps severity strings to numeric rank for comparison.
// Higher rank = more severe.
var severityRank = map[string]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
	"":               0,
}

// SeverityAtOrAbove reports whether resultSeverity is at or above the threshold.
func SeverityAtOrAbove(resultSeverity, threshold string) bool {
	return severityRank[resultSeverity] >= severityRank[threshold]
}

// CompareSeverity returns >0 if a is more severe than b, <0 if less, 0 if equal.
func CompareSeverity(a, b string) int {
	return severityRank[a] - severityRank[b]
}

// AssignSeverityAndConfidence enriches a Result with severity, confidence, and tags
// based on the finding characteristics. This is a pure function that does not
// mutate any shared state.
func AssignSeverityAndConfidence(r *Result) {
	// Default baseline
	r.Severity = SeverityInfo
	r.Confidence = ConfidenceTentative

	// Secret detection overrides everything — use the highest secret severity.
	if r.SecretFound && len(r.SecretTypes) > 0 {
		r.Severity = secretTypesToSeverity(r.SecretTypes)
		r.Confidence = ConfidenceConfirmed
		r.Tags = appendUnique(r.Tags, "secret")
	}

	// Bypass detection is high severity with firm confidence.
	if strings.Contains(r.Method, "BYPASS") || strings.HasSuffix(r.URL, " [BYPASS]") {
		if CompareSeverity(SeverityHigh, r.Severity) > 0 || r.Severity == SeverityInfo {
			r.Severity = SeverityHigh
		}
		if r.Confidence != ConfidenceConfirmed {
			r.Confidence = ConfidenceFirm
		}
		r.Tags = appendUnique(r.Tags, "bypass")
	}

	// Method fuzzing (405 → success with alternative method).
	if r.Method != "GET" && r.Method != "GET+BYPASS" && r.Method != "" {
		if r.Severity == SeverityInfo {
			r.Severity = SeverityMedium
		}
		if r.Confidence == ConfidenceTentative {
			r.Confidence = ConfidenceFirm
		}
		r.Tags = appendUnique(r.Tags, "method-fuzz")
	}

	// Critical flag was previously set by bypass/method-fuzz logic.
	if r.Critical && CompareSeverity(SeverityHigh, r.Severity) > 0 {
		r.Severity = SeverityHigh
		r.Confidence = ConfidenceFirm
	}

	// 401/403 are interesting but lower in isolation.
	if (r.StatusCode == 401 || r.StatusCode == 403) && r.Severity == SeverityInfo {
		r.Severity = SeverityLow
		r.Confidence = ConfidenceTentative
		r.Tags = appendUnique(r.Tags, "access-control")
	}

	// Directory listing (redirect-based detection).
	// Note: must come after access-control check since isDirectory also matches 403.
	if isDirectory(r) && r.Severity == SeverityInfo {
		r.Severity = SeverityLow
		r.Tags = appendUnique(r.Tags, "directory")
	}

	// WAF detection is informational.
	if r.WAFDetected != "" {
		r.Tags = appendUnique(r.Tags, "waf")
	}
}

// secretTypesToSeverity maps detected secret types to the highest applicable severity.
func secretTypesToSeverity(secretTypes []string) string {
	highest := SeverityInfo
	criticalPatterns := []string{"AWS", "Private Key", "GitHub Token", "Stripe Secret", "Database Connection"}
	highPatterns := []string{"JWT", "Slack", "Google API", "Heroku", "Mailgun", "Twilio"}

	for _, st := range secretTypes {
		for _, cp := range criticalPatterns {
			if strings.Contains(st, cp) && CompareSeverity(SeverityCritical, highest) > 0 {
				highest = SeverityCritical
			}
		}
		for _, hp := range highPatterns {
			if strings.Contains(st, hp) && CompareSeverity(SeverityHigh, highest) > 0 {
				highest = SeverityHigh
			}
		}
		if highest == SeverityInfo {
			highest = SeverityMedium
		}
	}
	return highest
}

func appendUnique(slice []string, val string) []string {
	for _, v := range slice {
		if v == val {
			return slice
		}
	}
	return append(slice, val)
}
