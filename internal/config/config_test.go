package config

import (
	"os"
	"testing"
)

func TestValidate_NoTargets(t *testing.T) {
	cfg := &Config{Wordlist: "dummy", LogLevel: "info"}
	err := Validate(cfg, []string{})
	if err == nil {
		t.Error("expected error for no targets")
	}
}

func TestValidate_MissingWordlist(t *testing.T) {
	cfg := &Config{Wordlist: "", LogLevel: "info"}
	err := Validate(cfg, []string{"http://example.com"})
	if err == nil {
		t.Error("expected error for missing wordlist")
	}
}

func TestValidate_WordlistNotFound(t *testing.T) {
	cfg := &Config{Wordlist: "/nonexistent/path/wordlist.txt", LogLevel: "info"}
	err := Validate(cfg, []string{"http://example.com"})
	if err == nil {
		t.Error("expected error for nonexistent wordlist")
	}
}

func TestValidate_URLNormalization(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{Wordlist: wordlist.Name(), LogLevel: "info", Threads: 50, Timeout: 10}
	targets := []string{"example.com", "https://secure.com", "http://plain.com"}
	err = Validate(cfg, targets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if targets[0] != "http://example.com" {
		t.Errorf("expected http://example.com, got %s", targets[0])
	}
	if targets[1] != "https://secure.com" {
		t.Errorf("expected https://secure.com unchanged, got %s", targets[1])
	}
	if targets[2] != "http://plain.com" {
		t.Errorf("expected http://plain.com unchanged, got %s", targets[2])
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{Wordlist: wordlist.Name(), LogLevel: "info", Threads: 50, Timeout: 10}
	err = Validate(cfg, []string{"http://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{Wordlist: wordlist.Name(), LogLevel: "invalid", Threads: 50, Timeout: 10}
	err = Validate(cfg, []string{"http://example.com"})
	if err == nil {
		t.Error("expected error for invalid log level")
	}
}

func TestValidate_InvalidThreads(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{Wordlist: wordlist.Name(), LogLevel: "info", Threads: -1}
	err = Validate(cfg, []string{"http://example.com"})
	if err == nil {
		t.Error("expected error for negative threads")
	}
}

func TestHeaderFlags(t *testing.T) {
	var h headerFlags

	if h.String() != "" {
		t.Errorf("expected empty string, got %q", h.String())
	}

	h.Set("Authorization: Bearer token")
	h.Set("X-Custom: value")

	if len(h) != 2 {
		t.Errorf("expected 2 headers, got %d", len(h))
	}

	str := h.String()
	if str == "" {
		t.Error("expected non-empty string")
	}
}

func TestStringSliceFlag(t *testing.T) {
	var s stringSliceFlag

	s.Set("*.example.com")
	s.Set("*.test.com")

	if len(s) != 2 {
		t.Errorf("expected 2 patterns, got %d", len(s))
	}
}

func TestEnvOrDefault(t *testing.T) {
	result := envOrDefault("NONEXISTENT_VAR_12345", 42)
	if result != 42 {
		t.Errorf("expected default 42, got %d", result)
	}
}

func TestEnvOrDefaultStr(t *testing.T) {
	result := envOrDefaultStr("NONEXISTENT_VAR_12345", "default")
	if result != "default" {
		t.Errorf("expected 'default', got %q", result)
	}
}

func TestValidate_FailOnValid(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		cfg := &Config{Wordlist: wordlist.Name(), LogLevel: "info", Threads: 50, Timeout: 10, FailOn: sev}
		err := Validate(cfg, []string{"http://example.com"})
		if err != nil {
			t.Errorf("expected no error for --fail-on %s, got %v", sev, err)
		}
	}
}

func TestValidate_FailOnInvalid(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{Wordlist: wordlist.Name(), LogLevel: "info", Threads: 50, Timeout: 10, FailOn: "invalid"}
	err = Validate(cfg, []string{"http://example.com"})
	if err == nil {
		t.Error("expected error for invalid --fail-on value")
	}
}

func TestValidate_FailOnEmpty(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{Wordlist: wordlist.Name(), LogLevel: "info", Threads: 50, Timeout: 10, FailOn: ""}
	err = Validate(cfg, []string{"http://example.com"})
	if err != nil {
		t.Errorf("expected no error for empty --fail-on, got %v", err)
	}
}
