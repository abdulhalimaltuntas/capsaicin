package diff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abdulhalimaltuntas/capsaicin/internal/scanner"
)

func res(url string, status int, sev string) scanner.Result {
	return scanner.Result{URL: url, StatusCode: status, Method: "GET", Severity: sev, Size: 100}
}

func TestCompareResults(t *testing.T) {
	baseline := []scanner.Result{
		res("https://h/a", 200, "low"),
		res("https://h/b", 403, "low"),
		res("https://h/gone", 200, "info"),
	}
	current := []scanner.Result{
		res("https://h/a", 200, "low"),      // unchanged
		res("https://h/b", 200, "high"),     // changed (status + severity)
		res("https://h/new", 200, "medium"), // new
	}

	report := CompareResults(current, baseline)
	if len(report.New) != 1 || report.New[0].URL != "https://h/new" {
		t.Errorf("expected 1 new (h/new), got %+v", report.New)
	}
	if len(report.Changed) != 1 || report.Changed[0].After.URL != "https://h/b" {
		t.Errorf("expected 1 changed (h/b), got %+v", report.Changed)
	}
	if len(report.Removed) != 1 || report.Removed[0].URL != "https://h/gone" {
		t.Errorf("expected 1 removed (h/gone), got %+v", report.Removed)
	}
	if !report.HasChanges() {
		t.Error("HasChanges should be true")
	}
}

func TestCompareResultsNoChange(t *testing.T) {
	same := []scanner.Result{res("https://h/a", 200, "low")}
	report := CompareResults(same, same)
	if report.HasChanges() {
		t.Errorf("identical scans should have no changes: %+v", report)
	}
}

func TestLoadBaselineMissing(t *testing.T) {
	m, err := LoadBaseline(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if err != nil {
		t.Fatalf("missing baseline should not error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("missing baseline should be empty, got %d", len(m))
	}
}

func TestCompareFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.jsonl")
	content := `{"url":"https://h/a","status_code":200,"method":"GET","severity":"low"}
{"url":"https://h/old","status_code":200,"method":"GET","severity":"info"}
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	current := []scanner.Result{res("https://h/a", 200, "low"), res("https://h/fresh", 200, "high")}
	report, err := Compare(current, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.New) != 1 || report.New[0].URL != "https://h/fresh" {
		t.Errorf("expected h/fresh new, got %+v", report.New)
	}
	if len(report.Removed) != 1 || report.Removed[0].URL != "https://h/old" {
		t.Errorf("expected h/old removed, got %+v", report.Removed)
	}
}
