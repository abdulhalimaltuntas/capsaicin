package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	TargetURL     string
	Wordlist      string
	Threads       int
	Extensions    []string
	Timeout       int
	OutputFile    string
	HTMLReport    string
	Verbose       bool
	MaxDepth      int
	CustomHeaders map[string]string
	RateLimit     int
	MaxResponseMB int
	RetryAttempts int
	LogLevel      string
	DryRun        bool
	AllowPatterns []string
	DenyPatterns  []string
	SafeMode      bool
	FailOn        string
}

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func envOrDefault(envKey string, defaultVal int) int {
	if val := os.Getenv(envKey); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return defaultVal
}

func envOrDefaultStr(envKey string, defaultVal string) string {
	if val := os.Getenv(envKey); val != "" {
		return val
	}
	return defaultVal
}

func Parse() Config {
	config := Config{
		CustomHeaders: make(map[string]string),
	}

	var headers headerFlags
	var allowPatterns stringSliceFlag
	var denyPatterns stringSliceFlag

	flag.StringVar(&config.TargetURL, "u", "", "Target URL (or use STDIN for multiple targets)")
	flag.StringVar(&config.Wordlist, "w", "", "Wordlist path (required)")
	flag.IntVar(&config.Threads, "t", envOrDefault("CAPSAICIN_THREADS", 50), "Number of concurrent threads")
	extensions := flag.String("x", "", "Extensions (comma-separated, e.g., php,html,txt)")
	flag.IntVar(&config.Timeout, "timeout", envOrDefault("CAPSAICIN_TIMEOUT", 10), "Request timeout in seconds")
	flag.StringVar(&config.OutputFile, "o", "", "Output file (JSON format)")
	flag.StringVar(&config.HTMLReport, "html", "", "Generate HTML report")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose mode")
	flag.IntVar(&config.MaxDepth, "depth", 0, "Recursive scanning depth (0=disabled)")
	flag.Var(&headers, "H", "Custom header (can be used multiple times)")
	flag.IntVar(&config.RateLimit, "rate-limit", envOrDefault("CAPSAICIN_RATE_LIMIT", 0), "Max requests per second per host (0=unlimited)")
	flag.IntVar(&config.MaxResponseMB, "max-response-mb", 10, "Max response body size in MB")
	flag.IntVar(&config.RetryAttempts, "retries", 2, "Number of retry attempts for failed requests")
	flag.StringVar(&config.LogLevel, "log-level", envOrDefaultStr("CAPSAICIN_LOG_LEVEL", "info"), "Log level (debug|info|warn|error)")
	flag.BoolVar(&config.DryRun, "dry-run", false, "Show what would be scanned without scanning")
	flag.Var(&allowPatterns, "allow", "Allow domain pattern (repeatable)")
	flag.Var(&denyPatterns, "deny", "Deny domain pattern (repeatable)")
	flag.BoolVar(&config.SafeMode, "safe-mode", false, "Disable bypass attempts and aggressive techniques")
	flag.StringVar(&config.FailOn, "fail-on", "", "Exit with code 2 if findings meet severity threshold (critical|high|medium|low|info)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: capsaicin [options]\n\n")
		fmt.Fprintf(os.Stderr, "Required:\n")
		fmt.Fprintf(os.Stderr, "  -u string       Target URL (or pipe via STDIN)\n")
		fmt.Fprintf(os.Stderr, "  -w string       Path to wordlist file\n\n")
		fmt.Fprintf(os.Stderr, "Optional:\n")
		fmt.Fprintf(os.Stderr, "  -t int          Concurrent threads (default: 50, env: CAPSAICIN_THREADS)\n")
		fmt.Fprintf(os.Stderr, "  -x string       Extensions (comma-separated)\n")
		fmt.Fprintf(os.Stderr, "  -H string       Custom headers (repeatable)\n")
		fmt.Fprintf(os.Stderr, "  --timeout int   Request timeout in seconds (default: 10, env: CAPSAICIN_TIMEOUT)\n")
		fmt.Fprintf(os.Stderr, "  --depth int     Recursive scanning depth (0=disabled)\n")
		fmt.Fprintf(os.Stderr, "  --rate-limit int Max req/s per host (default: 0, env: CAPSAICIN_RATE_LIMIT)\n")
		fmt.Fprintf(os.Stderr, "  --retries int   Retry attempts (default: 2)\n")
		fmt.Fprintf(os.Stderr, "  --log-level str Log level: debug|info|warn|error (default: info)\n")
		fmt.Fprintf(os.Stderr, "  --dry-run       Show scan plan without executing\n")
		fmt.Fprintf(os.Stderr, "  --allow pattern Allow domain pattern (repeatable)\n")
		fmt.Fprintf(os.Stderr, "  --deny pattern  Deny domain pattern (repeatable)\n")
		fmt.Fprintf(os.Stderr, "  --safe-mode     Disable bypass attempts\n")
		fmt.Fprintf(os.Stderr, "  --fail-on str   Exit code 2 if severity >= threshold (critical|high|medium|low|info)\n")
		fmt.Fprintf(os.Stderr, "  -v              Verbose mode\n")
		fmt.Fprintf(os.Stderr, "  -o string       JSON output file\n")
		fmt.Fprintf(os.Stderr, "  --html string   HTML report file\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  capsaicin -u https://target.com -w wordlist.txt\n")
		fmt.Fprintf(os.Stderr, "  cat targets.txt | capsaicin -w words.txt -t 100\n")
		fmt.Fprintf(os.Stderr, "  CAPSAICIN_THREADS=20 capsaicin -u https://target.com -w wordlist.txt\n")
	}

	flag.Parse()

	if *extensions != "" {
		config.Extensions = strings.Split(*extensions, ",")
		for i := range config.Extensions {
			config.Extensions[i] = strings.TrimSpace(config.Extensions[i])
			if !strings.HasPrefix(config.Extensions[i], ".") {
				config.Extensions[i] = "." + config.Extensions[i]
			}
		}
	}

	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			config.CustomHeaders[key] = value
		}
	}

	config.AllowPatterns = allowPatterns
	config.DenyPatterns = denyPatterns

	return config
}

func Validate(config *Config, targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified. Use -u flag or pipe targets via STDIN")
	}

	for i := range targets {
		if !strings.HasPrefix(targets[i], "http://") && !strings.HasPrefix(targets[i], "https://") {
			targets[i] = "http://" + targets[i]
		}
	}

	if config.Wordlist == "" {
		return fmt.Errorf("wordlist is required (-w). Provide a wordlist file path")
	}

	if _, err := os.Stat(config.Wordlist); os.IsNotExist(err) {
		return fmt.Errorf("wordlist file not found: %s. Check the path and try again", config.Wordlist)
	}

	if config.Threads <= 0 {
		return fmt.Errorf("threads must be positive, got %d. Use -t to set (default: 50)", config.Threads)
	}

	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %d. Use --timeout to set (default: 10)", config.Timeout)
	}

	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[config.LogLevel] {
		return fmt.Errorf("invalid log level %q. Valid values: debug, info, warn, error", config.LogLevel)
	}

	if config.FailOn != "" {
		validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
		if !validSeverities[config.FailOn] {
			return fmt.Errorf("invalid --fail-on value %q. Valid values: critical, high, medium, low, info", config.FailOn)
		}
	}

	return nil
}
