package scanner

// Exit codes for CI integration.
const (
	ExitOK              = 0
	ExitScanError       = 1
	ExitThresholdFailed = 2
)

func DetermineExitCode(results []Result, threshold string) int {
	if threshold == "" {
		return ExitOK
	}

	for i := range results {
		if SeverityAtOrAbove(results[i].Severity, threshold) {
			return ExitThresholdFailed
		}
	}
	return ExitOK
}
