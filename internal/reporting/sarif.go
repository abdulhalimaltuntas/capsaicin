package reporting

import (
	"encoding/json"

	"github.com/abdulhalimaltuntas/capsaicin/internal/scanner"
)

// SARIF (Static Analysis Results Interchange Format) 2.1.0 output lets findings
// flow into GitHub code scanning and other security dashboards.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// SaveSARIF writes findings as SARIF 2.1.0.
func SaveSARIF(results []scanner.Result, filename string) error {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	SortResults(sorted)

	ruleSet := map[string]bool{}
	var rules []sarifRule
	var sr []sarifResult

	for i := range sorted {
		r := &sorted[i]
		rid := ruleID(r)
		if !ruleSet[rid] {
			ruleSet[rid] = true
			rules = append(rules, sarifRule{ID: rid, Name: rid})
		}
		sr = append(sr, sarifResult{
			RuleID:  rid,
			Level:   sarifLevel(r.Severity),
			Message: sarifMessage{Text: sarifText(r)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: r.URL}},
			}},
		})
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Capsaicin",
				Version:        "3.1.0",
				InformationURI: "https://github.com/abdulhalimaltuntas/capsaicin",
				Rules:          rules,
			}},
			Results: sr,
		}},
	}

	f, err := createOutput(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func ruleID(r *scanner.Result) string {
	switch {
	case r.SecretFound:
		return "exposed-secret"
	case len(r.Tags) > 0 && r.Tags[0] == "bypass":
		return "access-control-bypass"
	case r.StatusCode == 401 || r.StatusCode == 403:
		return "restricted-endpoint"
	default:
		return "discovered-endpoint"
	}
}

func sarifLevel(severity string) string {
	switch severity {
	case scanner.SeverityCritical, scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifText(r *scanner.Result) string {
	msg := "Discovered " + r.URL + " (HTTP " + itoa(r.StatusCode) + ")"
	if r.SecretFound && len(r.SecretTypes) > 0 {
		msg += " — secret(s): " + join(r.SecretTypes)
	}
	if r.WAFDetected != "" {
		msg += " — WAF: " + r.WAFDetected
	}
	return msg
}
