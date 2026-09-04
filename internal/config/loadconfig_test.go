package config

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func loadWith(t *testing.T, args ...string) *Config {
	t.Helper()
	viper.Reset()
	cmd := &cobra.Command{RunE: func(*cobra.Command, []string) error { return nil }}
	InitFlags(cmd)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	cfg, err := LoadConfig(cmd)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

func TestLoadConfig_Basics(t *testing.T) {
	cfg := loadWith(t, "-u", "https://x.com", "-w", "words.txt",
		"-X", "post", "--extensions", "php,html", "-H", "X-Test: 1", "--vhost",
		"--resolvers", "1.1.1.1", "--sni", "example.com", "--verify-secrets",
		"--webhook", "https://hooks.slack.com/x", "--no-color", "--silent")

	if cfg.TargetURL != "https://x.com" {
		t.Errorf("url: %q", cfg.TargetURL)
	}
	if cfg.Method != "POST" { // uppercased
		t.Errorf("method not uppercased: %q", cfg.Method)
	}
	if len(cfg.Extensions) != 2 || cfg.Extensions[0] != ".php" {
		t.Errorf("extensions: %v", cfg.Extensions)
	}
	if cfg.CustomHeaders["X-Test"] != "1" {
		t.Errorf("headers: %v", cfg.CustomHeaders)
	}
	if !cfg.VHost || !cfg.VerifySecrets || !cfg.NoColor || !cfg.Silent {
		t.Error("bool flags not parsed")
	}
	if len(cfg.Resolvers) != 1 || cfg.SNI != "example.com" || cfg.Webhook == "" {
		t.Error("network/notify flags not parsed")
	}
	if len(cfg.Wordlists) != 1 || cfg.Wordlists[0].Keyword != "FUZZ" {
		t.Errorf("wordlists: %v", cfg.Wordlists)
	}
}

func TestLoadConfig_DataFromFile(t *testing.T) {
	f, _ := os.CreateTemp("", "body-*.txt")
	defer os.Remove(f.Name())
	f.WriteString("payload=1")
	f.Close()

	cfg := loadWith(t, "-w", "w.txt", "-d", "@"+f.Name())
	if cfg.PostData != "payload=1" {
		t.Errorf("@file body not read: %q", cfg.PostData)
	}
}

func TestLoadConfig_MultiWordlist(t *testing.T) {
	cfg := loadWith(t, "-w", "a.txt:W1", "-w", "b.txt:W2")
	if len(cfg.Wordlists) != 2 {
		t.Fatalf("expected 2 wordlists, got %d", len(cfg.Wordlists))
	}
	if cfg.Wordlists[0].Keyword != "W1" || cfg.Wordlists[1].Keyword != "W2" {
		t.Errorf("keywords: %v", cfg.Wordlists)
	}
	if cfg.Wordlist != "a.txt" { // first path kept for compat
		t.Errorf("primary wordlist: %q", cfg.Wordlist)
	}
}

func TestParseWordlistSpec(t *testing.T) {
	cases := map[string]WordlistSpec{
		"list.txt":      {Path: "list.txt", Keyword: "FUZZ"},
		"list.txt:W1":   {Path: "list.txt", Keyword: "W1"},
		"/a/b.txt:HOST": {Path: "/a/b.txt", Keyword: "HOST"},
		"list.txt:low":  {Path: "list.txt:low", Keyword: "FUZZ"}, // lowercase not a keyword
	}
	for in, want := range cases {
		if got := ParseWordlistSpec(in); got != want {
			t.Errorf("ParseWordlistSpec(%q) = %+v; want %+v", in, got, want)
		}
	}
}

func TestValidateConfig_OutputFormats(t *testing.T) {
	f, _ := os.CreateTemp("", "wl-*.txt")
	defer os.Remove(f.Name())
	f.Close()
	base := func() *Config {
		return &Config{
			Wordlist: f.Name(), Threads: 10, Timeout: 5, MaxResponseMB: 10,
			RecalInterval: 500, Method: "GET", FuzzMode: "sniper",
			TLSImpersonate: "random", JitterProfile: "moderate",
			ProxyStrategy: "random", OutputFormat: "sarif", LogLevel: "info",
			MatchCodes: "200", WebhookMinSeverity: "high",
		}
	}
	if err := ValidateConfig(base()); err != nil {
		t.Errorf("valid sarif config rejected: %v", err)
	}
	bad := base()
	bad.OutputFormat = "xml"
	if ValidateConfig(bad) == nil {
		t.Error("expected invalid output-format to be rejected")
	}
	bad2 := base()
	bad2.WebhookMinSeverity = "bogus"
	if ValidateConfig(bad2) == nil {
		t.Error("expected invalid webhook-min-severity to be rejected")
	}
}
