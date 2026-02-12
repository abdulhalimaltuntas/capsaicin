package scanner

import "testing"

func TestDetermineExitCode_EmptyThreshold(t *testing.T) {
	results := []Result{{Severity: SeverityCritical}}
	code := DetermineExitCode(results, "")
	if code != ExitOK {
		t.Errorf("expected ExitOK for empty threshold, got %d", code)
	}
}

func TestDetermineExitCode_NoResults(t *testing.T) {
	code := DetermineExitCode(nil, "critical")
	if code != ExitOK {
		t.Errorf("expected ExitOK for no results, got %d", code)
	}
}

func TestDetermineExitCode_BelowThreshold(t *testing.T) {
	results := []Result{
		{Severity: SeverityLow},
		{Severity: SeverityInfo},
	}
	code := DetermineExitCode(results, "high")
	if code != ExitOK {
		t.Errorf("expected ExitOK for results below threshold, got %d", code)
	}
}

func TestDetermineExitCode_AtThreshold(t *testing.T) {
	results := []Result{
		{Severity: SeverityHigh},
	}
	code := DetermineExitCode(results, "high")
	if code != ExitThresholdFailed {
		t.Errorf("expected ExitThresholdFailed for results at threshold, got %d", code)
	}
}

func TestDetermineExitCode_AboveThreshold(t *testing.T) {
	results := []Result{
		{Severity: SeverityInfo},
		{Severity: SeverityCritical},
	}
	code := DetermineExitCode(results, "medium")
	if code != ExitThresholdFailed {
		t.Errorf("expected ExitThresholdFailed for results above threshold, got %d", code)
	}
}

func TestDetermineExitCode_InfoThreshold(t *testing.T) {
	results := []Result{
		{Severity: SeverityInfo},
	}
	code := DetermineExitCode(results, "info")
	if code != ExitThresholdFailed {
		t.Errorf("expected ExitThresholdFailed for info >= info, got %d", code)
	}
}

func TestExitCodeConstants(t *testing.T) {
	if ExitOK != 0 {
		t.Errorf("ExitOK should be 0")
	}
	if ExitScanError != 1 {
		t.Errorf("ExitScanError should be 1")
	}
	if ExitThresholdFailed != 2 {
		t.Errorf("ExitThresholdFailed should be 2")
	}
}
