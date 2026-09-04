package reporting

import (
	"encoding/csv"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/abdulhalimaltuntas/capsaicin/internal/scanner"
)

// SaveJSONL writes one JSON object per line (JSON Lines / NDJSON) — the format
// pipelines and log shippers consume most easily. Results are sorted for stable,
// diffable output.
func SaveJSONL(results []scanner.Result, filename string) error {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	SortResults(sorted)

	file, err := createOutput(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file) // Encoder appends a newline after each value.
	for i := range sorted {
		if err := enc.Encode(sorted[i]); err != nil {
			return err
		}
	}
	return nil
}

// SaveCSV writes results as a spreadsheet-friendly CSV with a header row.
func SaveCSV(results []scanner.Result, filename string) error {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	SortResults(sorted)

	file, err := createOutput(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()

	if err := w.Write([]string{
		"url", "status_code", "size", "word_count", "line_count", "method",
		"severity", "confidence", "secret_found", "secret_types",
		"waf_detected", "server", "powered_by", "tags",
	}); err != nil {
		return err
	}

	for i := range sorted {
		r := &sorted[i]
		row := []string{
			r.URL,
			strconv.Itoa(r.StatusCode),
			strconv.Itoa(r.Size),
			strconv.Itoa(r.WordCount),
			strconv.Itoa(r.LineCount),
			r.Method,
			r.Severity,
			r.Confidence,
			strconv.FormatBool(r.SecretFound),
			strings.Join(r.SecretTypes, ";"),
			r.WAFDetected,
			r.Server,
			r.PoweredBy,
			strings.Join(r.Tags, ";"),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}
