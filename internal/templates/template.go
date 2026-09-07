// Package templates implements a Nuclei-style YAML template engine: declarative,
// community-extensible HTTP checks with word/status/regex/header matchers and
// regex extractors. It turns Capsaicin from a pure discovery tool into an
// extensible vulnerability scanner — new checks are added as YAML files, no code.
package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Template is one declarative check.
type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"requests"`
	// HTTP is a nuclei-v2 alias for Requests; either key is accepted.
	HTTP []Request `yaml:"http"`
}

// Info is the human-facing metadata block.
type Info struct {
	Name     string `yaml:"name"`
	Author   string `yaml:"author"`
	Severity string `yaml:"severity"`
	Tags     string `yaml:"tags"`
}

// Request is a single HTTP interaction plus its matching logic.
type Request struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	MatchersCondition string            `yaml:"matchers-condition"` // and|or (default or)
	Matchers          []Matcher         `yaml:"matchers"`
	Extractors        []Extractor       `yaml:"extractors"`
}

// Matcher decides whether a response satisfies a condition.
type Matcher struct {
	Type      string   `yaml:"type"`      // word|status|regex|header
	Part      string   `yaml:"part"`      // body|header|status (default body)
	Words     []string `yaml:"words"`     // for type=word/header
	Status    []int    `yaml:"status"`    // for type=status
	Regex     []string `yaml:"regex"`     // for type=regex
	Condition string   `yaml:"condition"` // and|or across words/regex (default or)
	Negative  bool     `yaml:"negative"`  // invert the match
}

// Extractor pulls evidence out of a matched response.
type Extractor struct {
	Type  string   `yaml:"type"` // regex
	Regex []string `yaml:"regex"`
	Part  string   `yaml:"part"` // body|header (default body)
}

// resolvedRequests returns Requests, falling back to the HTTP alias.
func (t *Template) resolvedRequests() []Request {
	if len(t.Requests) > 0 {
		return t.Requests
	}
	return t.HTTP
}

// severity normalizes the declared severity, defaulting to info.
func (t *Template) severity() string {
	s := strings.ToLower(strings.TrimSpace(t.Info.Severity))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	default:
		return "info"
	}
}

// Load reads a single template file.
func Load(path string) (*Template, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Template
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	if t.ID == "" {
		t.ID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if len(t.resolvedRequests()) == 0 {
		return nil, fmt.Errorf("template %s has no requests", t.ID)
	}
	return &t, nil
}

// LoadDir loads every *.yaml/*.yml template under dir (recursively). Individual
// parse failures are collected and skipped so one bad file cannot abort the set.
func LoadDir(dir string) ([]*Template, []error) {
	var tmpls []*Template
	var errs []error
	for _, path := range collectYAML(dir) {
		t, lerr := Load(path)
		if lerr != nil {
			errs = append(errs, lerr)
			continue
		}
		tmpls = append(tmpls, t)
	}
	return tmpls, errs
}

// collectYAML returns the paths of every *.yaml/*.yml file under dir, recursing
// into subdirectories. Unreadable directories yield no paths (best-effort).
func collectYAML(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			files = append(files, collectYAML(full)...)
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, full)
		}
	}
	return files
}
