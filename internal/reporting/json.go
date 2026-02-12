package reporting

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/scanner"
)

type ScanReport struct {
	SchemaVersion string           `json:"schema_version"`
	RunID         string           `json:"run_id"`
	Metadata      ScanMetadata     `json:"metadata"`
	Summary       ScanSummary      `json:"summary"`
	Results       []scanner.Result `json:"results"`
}

type ScanMetadata struct {
	StartTime    string `json:"start_time"`
	EndTime      string `json:"end_time"`
	Duration     string `json:"duration"`
	TargetCount  int    `json:"target_count"`
	TargetsHash  string `json:"targets_hash"`
	TotalResults int    `json:"total_results"`
	Version      string `json:"version"`
	Profile      string `json:"profile,omitempty"`
}

type ScanSummary struct {
	TotalFindings    int            `json:"total_findings"`
	BySeverity       map[string]int `json:"by_severity"`
	SecretsFound     int            `json:"secrets_found"`
	CriticalFindings int            `json:"critical_findings"`
	MaxSeverity      string         `json:"max_severity"`
}

func SaveJSON(results []scanner.Result, filename string) error {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].URL != sorted[j].URL {
			return sorted[i].URL < sorted[j].URL
		}
		return sorted[i].StatusCode < sorted[j].StatusCode
	})

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sorted)
}

func SaveJSONReport(results []scanner.Result, filename string, targets []string, runID string, startTime time.Time, duration time.Duration) error {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].URL != sorted[j].URL {
			return sorted[i].URL < sorted[j].URL
		}
		return sorted[i].StatusCode < sorted[j].StatusCode
	})

	targetsHash := hashStrings(targets)
	summary := buildSummary(sorted)

	report := ScanReport{
		SchemaVersion: "3.1",
		RunID:         runID,
		Metadata: ScanMetadata{
			StartTime:    startTime.Format(time.RFC3339),
			EndTime:      startTime.Add(duration).Format(time.RFC3339),
			Duration:     duration.Round(time.Millisecond).String(),
			TargetCount:  len(targets),
			TargetsHash:  targetsHash,
			TotalResults: len(sorted),
			Version:      "3.1.0",
		},
		Summary: summary,
		Results: sorted,
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// buildSummary computes aggregate statistics from results for the report envelope.
func buildSummary(results []scanner.Result) ScanSummary {
	severityRank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

	summary := ScanSummary{
		TotalFindings: len(results),
		BySeverity:    map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
	}

	maxRank := 0
	for _, r := range results {
		if r.Severity != "" {
			summary.BySeverity[r.Severity]++
			if severityRank[r.Severity] > maxRank {
				maxRank = severityRank[r.Severity]
				summary.MaxSeverity = r.Severity
			}
		}
		if r.SecretFound {
			summary.SecretsFound++
		}
		if r.Critical {
			summary.CriticalFindings++
		}
	}
	return summary
}

func hashStrings(ss []string) string {
	h := sha256.New()
	for _, s := range ss {
		h.Write([]byte(s))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func GenerateRunID() string {
	h := sha256.New()
	h.Write([]byte(time.Now().Format(time.RFC3339Nano)))
	h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func SortResults(results []scanner.Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].URL != results[j].URL {
			return results[i].URL < results[j].URL
		}
		return results[i].StatusCode < results[j].StatusCode
	})
}

func FormatResultsJSON(results []scanner.Result) (string, error) {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	SortResults(sorted)

	data, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func CountByStatus(results []scanner.Result) map[string]int {
	counts := map[string]int{
		"2xx":      0,
		"3xx":      0,
		"4xx":      0,
		"5xx":      0,
		"critical": 0,
		"secrets":  0,
		"waf":      0,
	}

	for _, r := range results {
		switch {
		case r.StatusCode >= 200 && r.StatusCode < 300:
			counts["2xx"]++
		case r.StatusCode >= 300 && r.StatusCode < 400:
			counts["3xx"]++
		case r.StatusCode >= 400 && r.StatusCode < 500:
			counts["4xx"]++
		case r.StatusCode >= 500:
			counts["5xx"]++
		}
		if r.Critical {
			counts["critical"]++
		}
		if r.SecretFound {
			counts["secrets"]++
		}
		if r.WAFDetected != "" {
			counts["waf"]++
		}
	}

	_ = strings.TrimSpace

	return counts
}
