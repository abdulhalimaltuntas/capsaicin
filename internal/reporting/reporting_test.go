package reporting

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/capsaicin/scanner/internal/scanner"
)

func testResults() []scanner.Result {
	return []scanner.Result{
		{
			URL:        "http://example.com/admin",
			StatusCode: 200,
			Size:       1024,
			WordCount:  50,
			LineCount:  10,
			Method:     "GET",
			Timestamp:  "2025-01-01T00:00:00Z",
			UserAgent:  "test-agent",
		},
		{
			URL:         "http://example.com/secret",
			StatusCode:  200,
			Size:        512,
			WordCount:   25,
			LineCount:   5,
			Method:      "GET",
			Timestamp:   "2025-01-01T00:00:01Z",
			UserAgent:   "test-agent",
			SecretFound: true,
			SecretTypes: []string{"AWS Access Key"},
			Critical:    true,
		},
		{
			URL:         "http://example.com/api",
			StatusCode:  301,
			Size:        0,
			Method:      "GET",
			Timestamp:   "2025-01-01T00:00:02Z",
			UserAgent:   "test-agent",
			WAFDetected: "Cloudflare",
		},
	}
}

func TestSaveJSON_RoundTrip(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "results-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	results := testResults()

	if err := SaveJSON(results, tmpFile.Name()); err != nil {
		t.Fatalf("SaveJSON failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var loaded []scanner.Result
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(loaded) != len(results) {
		t.Fatalf("expected %d results, got %d", len(results), len(loaded))
	}

	for i := 1; i < len(loaded); i++ {
		if loaded[i].URL < loaded[i-1].URL {
			t.Errorf("results not sorted: %s before %s", loaded[i-1].URL, loaded[i].URL)
		}
	}
}

func TestSaveJSON_DeterministicOrdering(t *testing.T) {
	tmpFile1, _ := os.CreateTemp("", "results1-*.json")
	tmpFile2, _ := os.CreateTemp("", "results2-*.json")
	defer os.Remove(tmpFile1.Name())
	defer os.Remove(tmpFile2.Name())
	tmpFile1.Close()
	tmpFile2.Close()

	results := testResults()

	SaveJSON(results, tmpFile1.Name())
	SaveJSON(results, tmpFile2.Name())

	data1, _ := os.ReadFile(tmpFile1.Name())
	data2, _ := os.ReadFile(tmpFile2.Name())

	if string(data1) != string(data2) {
		t.Error("expected identical output for same inputs (deterministic ordering)")
	}
}

func TestSaveJSON_EmptyResults(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "results-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	if err := SaveJSON([]scanner.Result{}, tmpFile.Name()); err != nil {
		t.Fatalf("SaveJSON failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var loaded []scanner.Result
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(loaded) != 0 {
		t.Errorf("expected 0 results, got %d", len(loaded))
	}
}

func TestSaveJSON_InvalidPath(t *testing.T) {
	err := SaveJSON(testResults(), "/nonexistent/dir/results.json")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestSaveJSONReport_Versioned(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "report-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	results := testResults()
	targets := []string{"http://example.com"}
	startTime := time.Now().Add(-5 * time.Second)
	duration := 5 * time.Second

	if err := SaveJSONReport(results, tmpFile.Name(), targets, "test-run-123", startTime, duration); err != nil {
		t.Fatalf("SaveJSONReport failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	var report ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to unmarshal report: %v", err)
	}

	if report.SchemaVersion != "3.1" {
		t.Errorf("expected schema_version 3.1, got %s", report.SchemaVersion)
	}

	if report.RunID != "test-run-123" {
		t.Errorf("expected run_id test-run-123, got %s", report.RunID)
	}

	if report.Metadata.TargetCount != 1 {
		t.Errorf("expected 1 target, got %d", report.Metadata.TargetCount)
	}

	if report.Metadata.Duration == "" {
		t.Error("expected non-empty duration")
	}

	if len(report.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(report.Results))
	}

	if report.Summary.TotalFindings != 3 {
		t.Errorf("expected 3 total findings in summary, got %d", report.Summary.TotalFindings)
	}

	if report.Summary.SecretsFound != 1 {
		t.Errorf("expected 1 secret in summary, got %d", report.Summary.SecretsFound)
	}

	if report.Summary.CriticalFindings != 1 {
		t.Errorf("expected 1 critical in summary, got %d", report.Summary.CriticalFindings)
	}
}

func TestGenerateRunID(t *testing.T) {
	id1 := GenerateRunID()
	id2 := GenerateRunID()

	if len(id1) != 12 {
		t.Errorf("expected 12 char run ID, got %d", len(id1))
	}

	_ = id2
}

func TestCountByStatus(t *testing.T) {
	results := testResults()
	counts := CountByStatus(results)

	if counts["2xx"] != 2 {
		t.Errorf("expected 2xx=2, got %d", counts["2xx"])
	}
	if counts["3xx"] != 1 {
		t.Errorf("expected 3xx=1, got %d", counts["3xx"])
	}
	if counts["critical"] != 1 {
		t.Errorf("expected critical=1, got %d", counts["critical"])
	}
	if counts["secrets"] != 1 {
		t.Errorf("expected secrets=1, got %d", counts["secrets"])
	}
	if counts["waf"] != 1 {
		t.Errorf("expected waf=1, got %d", counts["waf"])
	}
}

func TestGenerateHTML_Basic(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "report-*.html")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	results := testResults()

	if err := GenerateHTML(results, tmpFile.Name()); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	html := string(data)

	if !strings.Contains(html, "Capsaicin Scan Report") {
		t.Error("expected title in HTML")
	}
	if !strings.Contains(html, "http://example.com/admin") {
		t.Error("expected admin URL in HTML")
	}
	if !strings.Contains(html, "CRITICAL") {
		t.Error("expected CRITICAL badge in HTML")
	}
	if !strings.Contains(html, "SECRET") {
		t.Error("expected SECRET badge in HTML")
	}
	if !strings.Contains(html, "WAF") {
		t.Error("expected WAF badge in HTML")
	}
	if !strings.Contains(html, "Cloudflare") {
		t.Error("expected Cloudflare WAF in HTML")
	}
}

func TestGenerateHTML_EmptyResults(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "report-*.html")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	if err := GenerateHTML([]scanner.Result{}, tmpFile.Name()); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if !strings.Contains(string(data), "Capsaicin Scan Report") {
		t.Error("expected title even with empty results")
	}
}

func TestGenerateHTML_InvalidPath(t *testing.T) {
	err := GenerateHTML(testResults(), "/nonexistent/dir/report.html")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}
