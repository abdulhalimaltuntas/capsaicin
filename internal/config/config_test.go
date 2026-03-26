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

func TestValidateConfig_MissingWordlist(t *testing.T) {
	cfg := &Config{Wordlist: "", LogLevel: "info"}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("expected error for missing wordlist")
	}
}

func TestValidateConfig_WordlistNotFound(t *testing.T) {
	cfg := &Config{Wordlist: "/nonexistent/path/wordlist.txt", LogLevel: "info"}
	err := ValidateConfig(cfg)
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

	cfg := &Config{
		Wordlist: wordlist.Name(),
		LogLevel: "info",
		Threads:  50,
		Timeout:  10,
		Method:   "GET",
		FuzzMode: "sniper",
		TLSImpersonate: "random",
		JitterProfile: "moderate",
		ProxyStrategy: "random",
		OutputFormat: "jsonl",
		MaxResponseMB: 10,
		ExtractDepth: 2,
		RecalInterval: 500,
	}
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

func TestValidateConfig_ValidConfig(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{
		Wordlist:       wordlist.Name(),
		LogLevel:       "info",
		Threads:        50,
		Timeout:        10,
		Method:         "GET",
		FuzzMode:       "dynamic",
		TLSImpersonate: "chrome",
		JitterProfile:  "stealth",
		ProxyStrategy:  "round_robin",
		OutputFormat:   "json",
		MaxResponseMB:  10,
		ExtractDepth:   2,
		RecalInterval:  500,
	}
	err = ValidateConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_InvalidLogLevel(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{
		Wordlist: wordlist.Name(),
		LogLevel: "invalid",
		Threads:  50,
		Timeout:  10,
		Method:   "GET",
		MaxResponseMB: 10,
		ExtractDepth: 2,
		RecalInterval: 500,
	}
	err = ValidateConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid log level")
	}
}

func TestValidateConfig_InvalidThreads(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{
		Wordlist: wordlist.Name(),
		LogLevel: "info",
		Threads:  -1,
	}
	err = ValidateConfig(cfg)
	if err == nil {
		t.Error("expected error for negative threads")
	}
}

func TestValidateConfig_FailOnValid(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		cfg := &Config{
			Wordlist: wordlist.Name(),
			LogLevel: "info",
			Threads:  50,
			Timeout:  10,
			FailOn:   sev,
			Method:   "GET",
			FuzzMode: "sniper",
			TLSImpersonate: "random",
			JitterProfile: "moderate",
			ProxyStrategy: "random",
			OutputFormat: "jsonl",
			MaxResponseMB: 10,
			ExtractDepth: 2,
			RecalInterval: 500,
		}
		err := ValidateConfig(cfg)
		if err != nil {
			t.Errorf("expected no error for --fail-on %s, got %v", sev, err)
		}
	}
}

func TestValidateConfig_FailOnInvalid(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{
		Wordlist: wordlist.Name(),
		LogLevel: "info",
		Threads:  50,
		Timeout:  10,
		FailOn:   "invalid",
		Method:   "GET",
		MaxResponseMB: 10,
		ExtractDepth: 2,
		RecalInterval: 500,
	}
	err = ValidateConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid --fail-on value")
	}
}

func TestValidateConfig_H3SocksConflict(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{
		Wordlist:       wordlist.Name(),
		Threads:        50,
		Timeout:        10,
		Method:         "GET",
		MaxResponseMB:  10,
		ExtractDepth:   2,
		RecalInterval:  500,
		FuzzMode:       "sniper",
		TLSImpersonate: "random",
		JitterProfile:  "moderate",
		ProxyStrategy:  "random",
		OutputFormat:   "jsonl",
		LogLevel:       "info",
		EnableHTTP3:    true,
		Proxy:          "socks5://127.0.0.1:9050",
	}
	err = ValidateConfig(cfg)
	if err == nil {
		t.Error("expected error for H3 + SOCKS5 proxy conflict")
	}
}

func TestValidateConfig_InvalidCodeSpec(t *testing.T) {
	wordlist, err := os.CreateTemp("", "wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.Close()

	cfg := &Config{
		Wordlist:      wordlist.Name(),
		Threads:       50,
		Timeout:       10,
		Method:        "GET",
		MaxResponseMB: 10,
		ExtractDepth:  2,
		RecalInterval: 500,
		MatchCodes:    "200-800", // invalid range
	}
	err = ValidateConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid match-code format")
	}

	cfg.MatchCodes = "abc"
	err = ValidateConfig(cfg)
	if err == nil {
		t.Error("expected error for non-integer match-code")
	}
}

func TestValidateCodeSpec(t *testing.T) {
	tests := []struct {
		spec    string
		isValid bool
	}{
		{"200", true},
		{"200,404,500", true},
		{"200-299", true},
		{"200-299,301,400-405", true},
		{"", true}, // empty is valid (skipped)
		{"99", false}, // too low
		{"600", false}, // too high
		{"200-", false}, // syntax
		{"-200", false}, // syntax
		{"300-200", false}, // lo > hi
		{"abc", false}, // not int
	}

	for _, tt := range tests {
		err := validateCodeSpec(tt.spec, "--test-flag")
		if tt.isValid && err != nil {
			t.Errorf("expected %q to be valid, got %v", tt.spec, err)
		}
		if !tt.isValid && err == nil {
			t.Errorf("expected %q to be invalid", tt.spec)
		}
	}
}
