package scanner

import "testing"

func TestAssignSeverityAndConfidence_SecretFound(t *testing.T) {
	r := &Result{
		URL:         "http://example.com/config",
		StatusCode:  200,
		Method:      "GET",
		SecretFound: true,
		SecretTypes: []string{"AWS Access Key"},
	}
	AssignSeverityAndConfidence(r)

	if r.Severity != SeverityCritical {
		t.Errorf("expected critical severity for AWS key, got %q", r.Severity)
	}
	if r.Confidence != ConfidenceConfirmed {
		t.Errorf("expected confirmed confidence for secret, got %q", r.Confidence)
	}
	if !containsTag(r.Tags, "secret") {
		t.Error("expected 'secret' tag")
	}
}

func TestAssignSeverityAndConfidence_BypassResult(t *testing.T) {
	r := &Result{
		URL:        "http://example.com/admin [BYPASS]",
		StatusCode: 200,
		Method:     "GET+BYPASS",
		Critical:   true,
	}
	AssignSeverityAndConfidence(r)

	if r.Severity != SeverityHigh {
		t.Errorf("expected high severity for bypass, got %q", r.Severity)
	}
	if r.Confidence != ConfidenceFirm {
		t.Errorf("expected firm confidence for bypass, got %q", r.Confidence)
	}
	if !containsTag(r.Tags, "bypass") {
		t.Error("expected 'bypass' tag")
	}
}

func TestAssignSeverityAndConfidence_MethodFuzz(t *testing.T) {
	r := &Result{
		URL:        "http://example.com/api",
		StatusCode: 200,
		Method:     "POST",
		Critical:   true,
	}
	AssignSeverityAndConfidence(r)

	if r.Severity != SeverityHigh {
		t.Errorf("expected high severity for critical method fuzz, got %q", r.Severity)
	}
	if !containsTag(r.Tags, "method-fuzz") {
		t.Error("expected 'method-fuzz' tag")
	}
}

func TestAssignSeverityAndConfidence_StandardOK(t *testing.T) {
	r := &Result{
		URL:        "http://example.com/page",
		StatusCode: 200,
		Method:     "GET",
	}
	AssignSeverityAndConfidence(r)

	if r.Severity != SeverityInfo {
		t.Errorf("expected info severity for standard 200, got %q", r.Severity)
	}
	if r.Confidence != ConfidenceTentative {
		t.Errorf("expected tentative confidence for standard 200, got %q", r.Confidence)
	}
}

func TestAssignSeverityAndConfidence_Directory(t *testing.T) {
	r := &Result{
		URL:        "http://example.com/dir/",
		StatusCode: 200,
		Method:     "GET",
	}
	AssignSeverityAndConfidence(r)

	if r.Severity != SeverityLow {
		t.Errorf("expected low severity for directory, got %q", r.Severity)
	}
	if !containsTag(r.Tags, "directory") {
		t.Error("expected 'directory' tag")
	}
}

func TestAssignSeverityAndConfidence_AccessControl(t *testing.T) {
	r := &Result{
		URL:        "http://example.com/secret",
		StatusCode: 403,
		Method:     "GET",
	}
	AssignSeverityAndConfidence(r)

	if r.Severity != SeverityLow {
		t.Errorf("expected low severity for 403, got %q", r.Severity)
	}
	if !containsTag(r.Tags, "access-control") {
		t.Error("expected 'access-control' tag")
	}
}

func TestAssignSeverityAndConfidence_WAFTag(t *testing.T) {
	r := &Result{
		URL:         "http://example.com/test",
		StatusCode:  200,
		Method:      "GET",
		WAFDetected: "Cloudflare",
	}
	AssignSeverityAndConfidence(r)

	if !containsTag(r.Tags, "waf") {
		t.Error("expected 'waf' tag")
	}
}

func TestAssignSeverityAndConfidence_SecretWithBypass(t *testing.T) {
	// Secret + bypass → secret severity should win (critical > high)
	r := &Result{
		URL:         "http://example.com/admin [BYPASS]",
		StatusCode:  200,
		Method:      "GET+BYPASS",
		Critical:    true,
		SecretFound: true,
		SecretTypes: []string{"AWS Access Key"},
	}
	AssignSeverityAndConfidence(r)

	if r.Severity != SeverityCritical {
		t.Errorf("expected critical severity (secret outranks bypass), got %q", r.Severity)
	}
	if r.Confidence != ConfidenceConfirmed {
		t.Errorf("expected confirmed confidence for secret, got %q", r.Confidence)
	}
	if !containsTag(r.Tags, "secret") || !containsTag(r.Tags, "bypass") {
		t.Errorf("expected both 'secret' and 'bypass' tags, got %v", r.Tags)
	}
}

func TestSeverityAtOrAbove(t *testing.T) {
	tests := []struct {
		result    string
		threshold string
		expected  bool
	}{
		{"critical", "critical", true},
		{"critical", "high", true},
		{"high", "critical", false},
		{"medium", "low", true},
		{"info", "info", true},
		{"low", "high", false},
		{"", "info", false},
	}

	for _, tt := range tests {
		got := SeverityAtOrAbove(tt.result, tt.threshold)
		if got != tt.expected {
			t.Errorf("SeverityAtOrAbove(%q, %q) = %v, expected %v", tt.result, tt.threshold, got, tt.expected)
		}
	}
}

func TestCompareSeverity(t *testing.T) {
	if CompareSeverity("critical", "high") <= 0 {
		t.Error("expected critical > high")
	}
	if CompareSeverity("low", "high") >= 0 {
		t.Error("expected low < high")
	}
	if CompareSeverity("medium", "medium") != 0 {
		t.Error("expected medium == medium")
	}
}

func TestSecretTypesToSeverity(t *testing.T) {
	tests := []struct {
		name     string
		types    []string
		expected string
	}{
		{"AWS key", []string{"AWS Access Key"}, SeverityCritical},
		{"JWT token", []string{"JWT Token"}, SeverityHigh},
		{"Generic", []string{"Generic Password"}, SeverityMedium},
		{"Multiple mixed", []string{"JWT Token", "AWS Access Key"}, SeverityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secretTypesToSeverity(tt.types)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestAppendUnique(t *testing.T) {
	s := appendUnique(nil, "a")
	s = appendUnique(s, "b")
	s = appendUnique(s, "a") // duplicate
	if len(s) != 2 {
		t.Errorf("expected 2 unique items, got %d", len(s))
	}
}

func containsTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}
