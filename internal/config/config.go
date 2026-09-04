package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ────────────────────────────────────────────────────────────────────────────
// Config is the single source of truth for all runtime options.
//
// Backward-compat: top-level fields that existing packages read (Wordlist,
// Threads, Timeout, SafeMode, MaxDepth, RateLimit, etc.) are kept directly
// on the struct so callers can construct Config literals in tests without
// touching the grouped sub-structs.
// ────────────────────────────────────────────────────────────────────────────

type Config struct {
	// ── Target & Request ──────────────────────────────────────────────────
	TargetURL     string            // -u / --url
	Wordlist      string            // -w / --wordlist
	Method        string            // -X / --method
	CustomHeaders map[string]string // -H / --header  (parsed from "Key: Value" slice)
	PostData      string            // -d / --data
	FuzzMode      string            // --mode  [sniper|clusterbomb|pitchfork|dynamic]

	// ── Evasion & Network ─────────────────────────────────────────────────
	ForceHTTP2     bool   // --h2
	EnableHTTP3    bool   // --h3
	TLSImpersonate string // --tls-impersonate  [chrome|firefox|safari|edge|random|none]
	HeaderRotation bool   // --header-rotation
	JitterProfile  string // --jitter  [aggressive|moderate|stealth|paranoid]
	Proxy          string // -x / --proxy
	ProxyFile      string // --proxy-file
	ProxyStrategy  string // --proxy-strategy  [round_robin|random|failover]

	// ── Smart Engine & Mutation ───────────────────────────────────────────
	AutoCalibrate bool   // -ac / --auto-calibrate
	RecalInterval int    // --recal-interval
	ExtractPaths  bool   // --extract-paths
	ExtractDepth  int    // --extract-depth
	TriggerConfig string // --trigger-config
	Spider        bool   // --spider (crawl target for seed words)

	// ── Adaptive / Headless ───────────────────────────────────────────────
	Headless     bool   // --headless (solve JS challenges via browser)
	ChromePath   string // --chrome-path (custom Chrome/Chromium binary)
	AdaptiveRate bool   // --adaptive-rate (bandit-driven bypass + auto slowdown)

	// ── Resilience ────────────────────────────────────────────────────────
	MaxDuration    int // --max-duration (whole-scan deadline in seconds; 0 = none)
	CBThreshold    int // --cb-threshold (per-host failures before circuit opens)
	CBResetSeconds int // --cb-reset (seconds a tripped circuit stays open)

	// ── Matchers & Filters ────────────────────────────────────────────────
	MatchCodes  string // -mc / --match-code
	MatchSize   string // -ms / --match-size
	MatchRegex  string // -mr / --match-regex
	FilterCodes string // -fc / --filter-code
	FilterSize  string // -fs / --filter-size
	FilterWords string // -fw / --filter-words

	// ── General / Output (includes backward-compat v1 fields) ─────────────
	Threads       int      // -t / --threads
	Timeout       int      // --timeout
	OutputFile    string   // -o / --output
	OutputFormat  string   // --output-format  [jsonl|json|html|csv]
	HTMLReport    string   // --html          (v1 compat)
	Resume        string   // --resume
	Debug         bool     // --debug
	Verbose       bool     // -v / --verbose
	MaxDepth      int      // --depth
	RateLimit     int      // --rate-limit
	MaxResponseMB int      // --max-response-mb
	RetryAttempts int      // --retries
	Extensions    []string // -x → note: reused short flag collision avoided
	LogLevel      string   // --log-level
	DryRun        bool     // --dry-run
	SafeMode      bool     // --safe-mode
	FailOn        string   // --fail-on
	AllowPatterns []string // --allow
	DenyPatterns  []string // --deny

	// ── Output & UX ───────────────────────────────────────────────────────
	NoColor bool // --no-color (also honors NO_COLOR / non-TTY)
	Silent  bool // --silent  (suppress banner/progress; only findings)

	// ── Network extras ────────────────────────────────────────────────────
	Resolvers []string // --resolvers (custom DNS, host:port, repeatable)
	SNI       string   // --sni       (TLS SNI override)

	// ── Detection extras ──────────────────────────────────────────────────
	VerifySecrets bool // --verify-secrets (opt-in live validation)
	VHost         bool // --vhost          (fuzz Host header instead of path)

	// ── Notifications ─────────────────────────────────────────────────────
	Webhook            string // --webhook              (Slack/Discord/generic)
	WebhookMinSeverity string // --webhook-min-severity

	// ── Internal (populated at runtime, not user-facing) ──────────────────
	RawHeaders  []string       // raw -H values before parsing
	InlineWords []string       // words injected in-process (e.g. cluster agent); bypasses Wordlist file
	Wordlists   []WordlistSpec // all -w entries (path[:KEYWORD]); drives multi-wordlist modes
}

// WordlistSpec is one -w entry: a file path and the keyword it fills in the URL
// (default "FUZZ"). Multiple specs enable clusterbomb/pitchfork fuzzing.
type WordlistSpec struct {
	Path    string
	Keyword string
}

// keywordRe matches a trailing ":KEYWORD" (uppercase alnum) in a -w value.
var keywordRe = regexp.MustCompile(`^(.*):([A-Z][A-Z0-9_]*)$`)

// ParseWordlistSpec splits "path:KEYWORD" into a spec, defaulting the keyword to
// FUZZ when absent. A bare path (or a path whose ':' suffix is not a keyword) is
// treated as the path itself.
func ParseWordlistSpec(v string) WordlistSpec {
	if m := keywordRe.FindStringSubmatch(v); m != nil {
		return WordlistSpec{Path: m[1], Keyword: m[2]}
	}
	return WordlistSpec{Path: v, Keyword: "FUZZ"}
}

// ────────────────────────────────────────────────────────────────────────────
// InitFlags registers every flag on the cobra command and binds to viper.
// Call this from NewRootCmd().
// ────────────────────────────────────────────────────────────────────────────

func InitFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	pf := cmd.PersistentFlags()

	// ── Target & Request ──────────────────────────────────────────────────
	f.StringP("url", "u", "", "Target URL (supports FUZZ keyword)")
	f.StringArrayP("wordlist", "w", nil, "Wordlist path[:KEYWORD], repeatable (clusterbomb/pitchfork)")
	f.StringP("method", "X", "GET", "HTTP method")
	f.StringSliceP("header", "H", nil, `Custom header ("Name: Value"), repeatable`)
	f.StringP("data", "d", "", "POST body data")
	f.String("mode", "sniper", "Fuzzing mode [sniper|clusterbomb|pitchfork|dynamic]")

	// ── Evasion & Network ─────────────────────────────────────────────────
	f.Bool("h2", false, "uTLS JA3/JA4 HTTP/2 impersonation (falls back to HTTP/1.1 for http:// and h1-only hosts)")
	f.Bool("h3", false, "Enable experimental HTTP/3 (QUIC) transport")
	f.String("tls-impersonate", "random", "JA3/JA4 spoofing profile [chrome|firefox|safari|edge|random|none]")
	f.Bool("header-rotation", false, "Auto-rotate User-Agent and Sec-CH-UA coherently")
	f.String("jitter", "moderate", "Stochastic delay profile [aggressive|moderate|stealth|paranoid]")
	f.StringP("proxy", "x", "", "Proxy URL (HTTP/SOCKS5)")
	f.String("proxy-file", "", "File containing proxy list (one per line)")
	f.String("proxy-strategy", "random", "Proxy rotation strategy [round_robin|random|failover]")

	// ── Smart Engine & Mutation ───────────────────────────────────────────
	f.Bool("auto-calibrate", false, "Enable Smart Anomaly Detection (DOM Hash + Length Clustering)")
	f.Int("recal-interval", 500, "Requests between rolling recalibration probes")
	f.Bool("extract-paths", false, "On-the-fly JS/HTML scraping for new endpoints")
	f.Int("extract-depth", 2, "Max recursion depth for extracted paths")
	f.String("trigger-config", "", "YAML file with exploit triggers/webhooks")
	f.Bool("spider", false, "Crawl target (robots/sitemap/JS) for seed words before scanning")

	// ── Adaptive & Headless ───────────────────────────────────────────────
	f.Bool("headless", false, "Solve JS challenges (Cloudflare/DataDome/reCAPTCHA) with a headless browser")
	f.String("chrome-path", "", "Custom Chrome/Chromium binary path for --headless")
	f.Bool("adaptive-rate", false, "Bandit-driven bypass selection + automatic slowdown on blocking")

	// ── Resilience ────────────────────────────────────────────────────────
	f.Int("max-duration", 0, "Whole-scan deadline in seconds (0 = no global deadline)")
	f.Int("cb-threshold", 20, "Per-host consecutive failures before the circuit breaker opens")
	f.Int("cb-reset", 30, "Seconds a tripped circuit breaker stays open before retrying a host")

	// ── Matchers & Filters ────────────────────────────────────────────────
	f.String("match-code", "200-299,301,302,307,401,403,405", "Match HTTP status codes")
	f.String("match-size", "", "Match response size")
	f.String("match-regex", "", "Match regexp in response body")
	f.String("filter-code", "", "Filter (exclude) HTTP status codes")
	f.String("filter-size", "", "Filter (exclude) response size")
	f.String("filter-words", "", "Filter (exclude) by word count")

	// ── General & Output ──────────────────────────────────────────────────
	f.IntP("threads", "t", 40, "Concurrent request workers")
	f.Int("timeout", 10, "Request timeout in seconds")
	f.StringP("output", "o", "", "Output file path")
	f.String("output-format", "jsonl", "Output format [jsonl|json|html|csv]")
	f.String("html", "", "HTML report output file (v1 compat)")
	f.String("resume", "", "Session state file for resuming scans")
	pf.Bool("debug", false, "Enable verbose internal debug logging")
	f.BoolP("verbose", "v", false, "Verbose output")
	f.Int("depth", 0, "Recursive scan depth (0 = disabled)")
	f.Int("rate-limit", 0, "Max requests/sec per host (0 = unlimited)")
	f.Int("max-response-mb", 10, "Max response body size in MB")
	f.Int("retries", 2, "Retry attempts for failed requests")
	f.StringP("extensions", "e", "", "File extensions to probe (comma-separated, e.g. php,html,txt)")
	f.String("log-level", "info", "Log level [debug|info|warn|error]")
	f.Bool("dry-run", false, "Show scan plan without executing")
	f.Bool("safe-mode", false, "Disable bypass attempts and method fuzzing")
	f.String("fail-on", "", "Exit code 2 if severity >= threshold [critical|high|medium|low|info]")
	f.StringSlice("allow", nil, "Allowed domain pattern (repeatable)")
	f.StringSlice("deny", nil, "Denied domain pattern (repeatable)")

	// ── Output & UX ────────────────────────────────────────────────────────
	f.Bool("no-color", false, "Disable ANSI colors (also honors NO_COLOR and non-TTY)")
	f.Bool("silent", false, "Suppress banner/progress; emit only findings")

	// ── Network extras ─────────────────────────────────────────────────────
	f.StringSlice("resolvers", nil, "Custom DNS resolver(s) host:port (repeatable)")
	f.String("sni", "", "TLS SNI override (defaults to target host)")

	// ── Detection extras ───────────────────────────────────────────────────
	f.Bool("verify-secrets", false, "Live-validate detected secrets (read-only, opt-in)")
	f.Bool("vhost", false, "Virtual-host fuzzing: fuzz the Host header instead of the path")

	// ── Notifications ──────────────────────────────────────────────────────
	f.String("webhook", "", "Webhook URL to notify on findings (Slack/Discord/generic JSON)")
	f.String("webhook-min-severity", "high", "Minimum severity to trigger --webhook")

	// ── Cobra shorthands for matcher/filter ────────────────────────────────
	// Register aliases using MarkShorthandDeprecated-free approach:
	// we define direct short flags for the most common matchers.
	cmd.Flags().Lookup("match-code").Shorthand = "" // avoid collision
	cmd.Flags().Lookup("match-size").Shorthand = ""
	cmd.Flags().Lookup("match-regex").Shorthand = ""
	cmd.Flags().Lookup("filter-code").Shorthand = ""
	cmd.Flags().Lookup("filter-size").Shorthand = ""
	cmd.Flags().Lookup("filter-words").Shorthand = ""

	// ── Viper env bindings ────────────────────────────────────────────────
	viper.SetEnvPrefix("CAPSAICIN")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// Bind key flags to env vars so CAPSAICIN_THREADS=20 just works.
	bindViperFlags(cmd, []string{
		"threads", "timeout", "rate-limit", "log-level",
		"retries", "max-response-mb", "jitter",
		"tls-impersonate", "output-format",
	})
}

// bindViperFlags binds a list of flag names to viper keys.
func bindViperFlags(cmd *cobra.Command, flags []string) {
	for _, name := range flags {
		if f := cmd.Flags().Lookup(name); f != nil {
			_ = viper.BindPFlag(name, f)
		}
		if f := cmd.PersistentFlags().Lookup(name); f != nil {
			_ = viper.BindPFlag(name, f)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// LoadConfig reads cobra flags + viper env overrides into a Config struct.
// ────────────────────────────────────────────────────────────────────────────

func LoadConfig(cmd *cobra.Command) (*Config, error) {
	f := cmd.Flags()

	getString := func(name string) string {
		if viper.IsSet(name) {
			return viper.GetString(name)
		}
		v, _ := f.GetString(name)
		return v
	}
	getInt := func(name string) int {
		if viper.IsSet(name) {
			return viper.GetInt(name)
		}
		v, _ := f.GetInt(name)
		return v
	}
	getBool := func(name string) bool {
		v, _ := f.GetBool(name)
		return v
	}
	getBoolPersist := func(name string) bool {
		v, _ := cmd.PersistentFlags().GetBool(name)
		return v
	}
	getStringSlice := func(name string) []string {
		v, _ := f.GetStringSlice(name)
		return v
	}

	// POST body: -d '@path' reads the body from a file (like curl).
	postData := getString("data")
	if strings.HasPrefix(postData, "@") {
		if b, err := os.ReadFile(postData[1:]); err == nil {
			postData = string(b)
		}
	}

	// Wordlists: -w path[:KEYWORD], repeatable. The first entry's path is kept in
	// Wordlist for backward-compatible single-wordlist callers.
	rawWordlists, _ := f.GetStringArray("wordlist")
	var wordlists []WordlistSpec
	for _, w := range rawWordlists {
		if strings.TrimSpace(w) != "" {
			wordlists = append(wordlists, ParseWordlistSpec(w))
		}
	}
	primaryWordlist := ""
	if len(wordlists) > 0 {
		primaryWordlist = wordlists[0].Path
	}

	rawHeaders := getStringSlice("header")
	customHeaders := make(map[string]string, len(rawHeaders))
	for _, h := range rawHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Parse extensions from comma-separated string.
	var extensions []string
	if ext := getString("extensions"); ext != "" {
		for _, e := range strings.Split(ext, ",") {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			extensions = append(extensions, e)
		}
	}

	cfg := &Config{
		// Target & Request
		TargetURL:     getString("url"),
		Wordlist:      primaryWordlist,
		Method:        strings.ToUpper(getString("method")),
		CustomHeaders: customHeaders,
		PostData:      postData,
		FuzzMode:      strings.ToLower(getString("mode")),

		// Evasion & Network
		ForceHTTP2:     getBool("h2"),
		EnableHTTP3:    getBool("h3"),
		TLSImpersonate: strings.ToLower(getString("tls-impersonate")),
		HeaderRotation: getBool("header-rotation"),
		JitterProfile:  strings.ToLower(getString("jitter")),
		Proxy:          getString("proxy"),
		ProxyFile:      getString("proxy-file"),
		ProxyStrategy:  strings.ToLower(getString("proxy-strategy")),

		// Smart Engine & Mutation
		AutoCalibrate: getBool("auto-calibrate"),
		RecalInterval: getInt("recal-interval"),
		ExtractPaths:  getBool("extract-paths"),
		ExtractDepth:  getInt("extract-depth"),
		TriggerConfig: getString("trigger-config"),
		Spider:        getBool("spider"),

		// Adaptive & Headless
		Headless:     getBool("headless"),
		ChromePath:   getString("chrome-path"),
		AdaptiveRate: getBool("adaptive-rate"),

		// Resilience
		MaxDuration:    getInt("max-duration"),
		CBThreshold:    getInt("cb-threshold"),
		CBResetSeconds: getInt("cb-reset"),

		// Matchers & Filters
		MatchCodes:  getString("match-code"),
		MatchSize:   getString("match-size"),
		MatchRegex:  getString("match-regex"),
		FilterCodes: getString("filter-code"),
		FilterSize:  getString("filter-size"),
		FilterWords: getString("filter-words"),

		// General
		Threads:       getInt("threads"),
		Timeout:       getInt("timeout"),
		OutputFile:    getString("output"),
		OutputFormat:  strings.ToLower(getString("output-format")),
		HTMLReport:    getString("html"),
		Resume:        getString("resume"),
		Debug:         getBoolPersist("debug"),
		Verbose:       getBool("verbose"),
		MaxDepth:      getInt("depth"),
		RateLimit:     getInt("rate-limit"),
		MaxResponseMB: getInt("max-response-mb"),
		RetryAttempts: getInt("retries"),
		Extensions:    extensions,
		LogLevel:      strings.ToLower(getString("log-level")),
		DryRun:        getBool("dry-run"),
		SafeMode:      getBool("safe-mode"),
		FailOn:        strings.ToLower(getString("fail-on")),
		AllowPatterns: getStringSlice("allow"),
		DenyPatterns:  getStringSlice("deny"),

		NoColor: getBool("no-color"),
		Silent:  getBool("silent"),

		Resolvers: getStringSlice("resolvers"),
		SNI:       getString("sni"),

		VerifySecrets: getBool("verify-secrets"),
		VHost:         getBool("vhost"),

		Webhook:            getString("webhook"),
		WebhookMinSeverity: strings.ToLower(getString("webhook-min-severity")),

		RawHeaders: rawHeaders,
		Wordlists:  wordlists,
	}

	return cfg, nil
}

// ────────────────────────────────────────────────────────────────────────────
// ValidateConfig performs exhaustive logical constraint checks.
// It returns the FIRST hard error encountered.  Soft warnings are collected
// in cfg itself (future: structured []Warning field).
// ────────────────────────────────────────────────────────────────────────────

func ValidateConfig(c *Config) error {
	var warnings []string

	// ── Required fields ───────────────────────────────────────────────────
	if c.Wordlist == "" && len(c.Wordlists) == 0 {
		return fmt.Errorf("wordlist is required (-w)")
	}
	for _, wl := range c.Wordlists {
		if _, err := os.Stat(wl.Path); os.IsNotExist(err) {
			return fmt.Errorf("wordlist file not found: %s", wl.Path)
		}
	}
	if len(c.Wordlists) == 0 && c.Wordlist != "" {
		if _, err := os.Stat(c.Wordlist); os.IsNotExist(err) {
			return fmt.Errorf("wordlist file not found: %s", c.Wordlist)
		}
	}

	// ── Numeric ranges ────────────────────────────────────────────────────
	if c.Threads <= 0 {
		return fmt.Errorf("--threads must be > 0, got %d", c.Threads)
	}
	if c.Threads > 10000 {
		return fmt.Errorf("--threads exceeds safety limit (10000), got %d", c.Threads)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("--timeout must be > 0, got %d", c.Timeout)
	}
	if c.MaxResponseMB <= 0 {
		return fmt.Errorf("--max-response-mb must be > 0, got %d", c.MaxResponseMB)
	}
	if c.RetryAttempts < 0 {
		return fmt.Errorf("--retries must be >= 0, got %d", c.RetryAttempts)
	}
	if c.MaxDepth < 0 {
		return fmt.Errorf("--depth must be >= 0, got %d", c.MaxDepth)
	}
	if c.RecalInterval < 10 {
		return fmt.Errorf("--recal-interval must be >= 10, got %d", c.RecalInterval)
	}
	if c.ExtractDepth < 0 || c.ExtractDepth > 10 {
		return fmt.Errorf("--extract-depth must be 0-10, got %d", c.ExtractDepth)
	}
	if c.MaxDuration < 0 {
		return fmt.Errorf("--max-duration must be >= 0, got %d", c.MaxDuration)
	}
	// 0 means "use the built-in default" (see transport.NewClient), so only
	// negative values are rejected here.
	if c.CBThreshold < 0 {
		return fmt.Errorf("--cb-threshold must be >= 0, got %d", c.CBThreshold)
	}
	if c.CBResetSeconds < 0 {
		return fmt.Errorf("--cb-reset must be >= 0, got %d", c.CBResetSeconds)
	}

	// ── Enum validations ──────────────────────────────────────────────────
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
	}
	if !validMethods[c.Method] {
		return fmt.Errorf("invalid HTTP method %q; valid: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE", c.Method)
	}

	validModes := map[string]bool{
		"sniper": true, "clusterbomb": true, "pitchfork": true, "dynamic": true,
	}
	if !validModes[c.FuzzMode] {
		return fmt.Errorf("invalid --mode %q; valid: sniper, clusterbomb, pitchfork, dynamic", c.FuzzMode)
	}

	validTLS := map[string]bool{
		"chrome": true, "firefox": true, "safari": true,
		"edge": true, "random": true, "none": true,
	}
	if !validTLS[c.TLSImpersonate] {
		return fmt.Errorf("invalid --tls-impersonate %q; valid: chrome, firefox, safari, edge, random, none", c.TLSImpersonate)
	}

	validJitter := map[string]bool{
		"aggressive": true, "moderate": true, "stealth": true, "paranoid": true,
	}
	if !validJitter[c.JitterProfile] {
		return fmt.Errorf("invalid --jitter %q; valid: aggressive, moderate, stealth, paranoid", c.JitterProfile)
	}

	validProxyStrategy := map[string]bool{
		"round_robin": true, "random": true, "failover": true,
	}
	if !validProxyStrategy[c.ProxyStrategy] {
		return fmt.Errorf("invalid --proxy-strategy %q; valid: round_robin, random, failover", c.ProxyStrategy)
	}

	validOutputFormat := map[string]bool{
		"jsonl": true, "json": true, "html": true, "csv": true, "sarif": true,
	}
	if !validOutputFormat[c.OutputFormat] {
		return fmt.Errorf("invalid --output-format %q; valid: jsonl, json, html, csv, sarif", c.OutputFormat)
	}

	if c.WebhookMinSeverity != "" {
		validSeverities := map[string]bool{
			"critical": true, "high": true, "medium": true, "low": true, "info": true,
		}
		if !validSeverities[c.WebhookMinSeverity] {
			return fmt.Errorf("invalid --webhook-min-severity %q; valid: critical, high, medium, low, info", c.WebhookMinSeverity)
		}
	}

	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid --log-level %q; valid: debug, info, warn, error", c.LogLevel)
	}

	if c.FailOn != "" {
		validSeverities := map[string]bool{
			"critical": true, "high": true, "medium": true, "low": true, "info": true,
		}
		if !validSeverities[c.FailOn] {
			return fmt.Errorf("invalid --fail-on %q; valid: critical, high, medium, low, info", c.FailOn)
		}
	}

	// ── Logical incompatibilities ─────────────────────────────────────────

	// H3 (QUIC/UDP) is incompatible with SOCKS5 proxies.
	if c.EnableHTTP3 && c.Proxy != "" {
		proxyURL, err := url.Parse(c.Proxy)
		if err == nil && strings.HasPrefix(strings.ToLower(proxyURL.Scheme), "socks") {
			return fmt.Errorf("--h3 (QUIC/UDP) is incompatible with SOCKS proxy %q; SOCKS tunnels TCP only", c.Proxy)
		}
	}

	// Proxy file must exist if specified.
	if c.ProxyFile != "" {
		if _, err := os.Stat(c.ProxyFile); os.IsNotExist(err) {
			return fmt.Errorf("proxy file not found: %s", c.ProxyFile)
		}
	}

	// Trigger config must exist if specified.
	if c.TriggerConfig != "" {
		if _, err := os.Stat(c.TriggerConfig); os.IsNotExist(err) {
			return fmt.Errorf("trigger config file not found: %s", c.TriggerConfig)
		}
	}

	// Resume file need not exist — it is created on first run and appended to,
	// then read back on subsequent runs to skip already-scanned URLs.

	// Proxy single + proxy file are mutually exclusive.
	if c.Proxy != "" && c.ProxyFile != "" {
		return fmt.Errorf("--proxy and --proxy-file are mutually exclusive; use one or the other")
	}

	// Match-code and filter-code format validation.
	if c.MatchCodes != "" {
		if err := validateCodeSpec(c.MatchCodes, "--match-code"); err != nil {
			return err
		}
	}
	if c.FilterCodes != "" {
		if err := validateCodeSpec(c.FilterCodes, "--filter-code"); err != nil {
			return err
		}
	}

	// Match-regex compilation check.
	if c.MatchRegex != "" {
		if _, err := regexp.Compile(c.MatchRegex); err != nil {
			return fmt.Errorf("invalid --match-regex pattern: %w", err)
		}
	}

	// ── Soft warnings (printed to stderr, do not block) ───────────────────
	if c.ExtractPaths && c.FuzzMode != "dynamic" {
		warnings = append(warnings,
			"[WARN] --extract-paths is most effective with --mode=dynamic; current mode: "+c.FuzzMode)
	}
	if c.EnableHTTP3 {
		warnings = append(warnings,
			"[WARN] --h3 negotiates QUIC; targets without HTTP/3 support will fail fast — pair with a retry or drop --h3")
	}
	if c.Headless && c.EnableHTTP3 {
		warnings = append(warnings,
			"[WARN] --headless drives a browser over its own stack; --h3 only affects the fast HTTP client")
	}
	if c.Threads > 500 && c.JitterProfile == "paranoid" {
		warnings = append(warnings,
			"[WARN] high thread count with paranoid jitter will severely limit throughput")
	}
	if c.SafeMode && (c.AutoCalibrate || c.ExtractPaths) {
		warnings = append(warnings,
			"[WARN] --safe-mode limits bypass/method-fuzz; calibration and extraction still operate")
	}

	// Emit warnings to stderr.
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, w)
	}

	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Validate is the backward-compatible shim used by existing code (main.go
// and tests).  It delegates to ValidateConfig plus the target-level checks.
// ────────────────────────────────────────────────────────────────────────────

func Validate(c *Config, targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified. Use -u flag or pipe targets via STDIN")
	}

	// URL normalization — adds http:// if missing.
	for i := range targets {
		if !strings.HasPrefix(targets[i], "http://") && !strings.HasPrefix(targets[i], "https://") {
			targets[i] = "http://" + targets[i]
		}
	}

	return ValidateConfig(c)
}

// ────────────────────────────────────────────────────────────────────────────
// validateCodeSpec checks that a status code spec (e.g. "200-299,301,403")
// is syntactically valid.
// ────────────────────────────────────────────────────────────────────────────

func validateCodeSpec(spec, flagName string) error {
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil {
				return fmt.Errorf("invalid %s range %q: must be integer-integer", flagName, part)
			}
			if lo < 100 || hi > 599 || lo > hi {
				return fmt.Errorf("invalid %s range %q: must be 100-599 with lo <= hi", flagName, part)
			}
		} else {
			code, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("invalid %s value %q: must be an integer", flagName, part)
			}
			if code < 100 || code > 599 {
				return fmt.Errorf("invalid %s value %d: must be 100-599", flagName, code)
			}
		}
	}
	return nil
}
