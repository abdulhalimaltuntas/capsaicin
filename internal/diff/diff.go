// Package diff compares a scan's findings against a prior JSONL baseline, so
// continuous/monitoring runs can surface only what changed — new endpoints,
// status/severity shifts, or findings that disappeared.
package diff

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/abdulhalimaltuntas/capsaicin/internal/scanner"
)

// Report is the delta between a baseline and the current scan.
type Report struct {
	New     []scanner.Result // present now, absent in baseline
	Changed []Change         // present in both but materially different
	Removed []scanner.Result // present in baseline, absent now
}

// Change pairs a baseline finding with its current counterpart.
type Change struct {
	Before scanner.Result
	After  scanner.Result
}

// HasChanges reports whether anything is different from the baseline.
func (r *Report) HasChanges() bool {
	return len(r.New) > 0 || len(r.Changed) > 0 || len(r.Removed) > 0
}

// key identifies a finding across runs by method + URL.
func key(r scanner.Result) string {
	return r.Method + " " + r.URL
}

// LoadBaseline reads a JSONL results file into a keyed map. A missing file yields
// an empty baseline (first run), never an error.
func LoadBaseline(path string) (map[string]scanner.Result, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		// A missing baseline is a first run, not an error.
		return map[string]scanner.Result{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]scanner.Result)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r scanner.Result
		if json.Unmarshal(line, &r) == nil && r.URL != "" {
			out[key(r)] = r
		}
	}
	return out, sc.Err()
}

// Compare produces the delta of current against the baseline at path.
func Compare(current []scanner.Result, baselinePath string) (*Report, error) {
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}
	return CompareMap(current, baseline), nil
}

// CompareResults diffs current against an in-memory baseline slice — used by
// continuous/monitor mode where the previous run is held in memory.
func CompareResults(current, baseline []scanner.Result) *Report {
	m := make(map[string]scanner.Result, len(baseline))
	for _, r := range baseline {
		m[key(r)] = r
	}
	return CompareMap(current, m)
}

// CompareMap diffs current against a keyed baseline map.
func CompareMap(current []scanner.Result, baseline map[string]scanner.Result) *Report {
	report := &Report{}
	currentKeys := make(map[string]bool, len(current))

	for _, r := range current {
		k := key(r)
		currentKeys[k] = true
		prev, ok := baseline[k]
		if !ok {
			report.New = append(report.New, r)
			continue
		}
		if materiallyDifferent(prev, r) {
			report.Changed = append(report.Changed, Change{Before: prev, After: r})
		}
	}

	for k, r := range baseline {
		if !currentKeys[k] {
			report.Removed = append(report.Removed, r)
		}
	}
	return report
}

// materiallyDifferent reports whether two findings for the same key differ in a
// way worth alerting on (status, severity, secret exposure, or a large size
// swing). Timestamps and minor byte jitter are ignored.
func materiallyDifferent(a, b scanner.Result) bool {
	if a.StatusCode != b.StatusCode || a.Severity != b.Severity || a.SecretFound != b.SecretFound {
		return true
	}
	delta := a.Size - b.Size
	if delta < 0 {
		delta = -delta
	}
	tolerance := a.Size / 10
	if tolerance < 64 {
		tolerance = 64
	}
	return delta > tolerance
}
