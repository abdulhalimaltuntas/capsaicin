package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	TargetURL      string
	Wordlist       string
	Threads        int
	Extensions     []string
	Timeout        int
	OutputFile     string
	HTMLReport     string
	Verbose        bool
	MaxDepth       int
	CustomHeaders  map[string]string
	RateLimit      int
	MaxResponseMB  int
	RetryAttempts  int
}

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func Parse() Config {
	config := Config{
		CustomHeaders: make(map[string]string),
	}

	var headers headerFlags

	flag.StringVar(&config.TargetURL, "u", "", "Target URL (or use STDIN for multiple targets)")
	flag.StringVar(&config.Wordlist, "w", "", "Wordlist path (required)")
	flag.IntVar(&config.Threads, "t", 50, "Number of concurrent threads")
	extensions := flag.String("x", "", "Extensions (comma-separated, e.g., php,html,txt)")
	flag.IntVar(&config.Timeout, "timeout", 10, "Request timeout in seconds")
	flag.StringVar(&config.OutputFile, "o", "", "Output file (JSON format)")
	flag.StringVar(&config.HTMLReport, "html", "", "Generate HTML report")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose mode")
	flag.IntVar(&config.MaxDepth, "depth", 0, "Recursive scanning depth (0=disabled)")
	flag.Var(&headers, "H", "Custom header (can be used multiple times)")
	flag.IntVar(&config.RateLimit, "rate-limit", 0, "Max requests per second per host (0=unlimited)")
	flag.IntVar(&config.MaxResponseMB, "max-response-mb", 10, "Max response body size in MB")
	flag.IntVar(&config.RetryAttempts, "retries", 2, "Number of retry attempts for failed requests")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: capsaicin [options]\n\n")
		fmt.Fprintf(os.Stderr, "Required:\n")
		fmt.Fprintf(os.Stderr, "  -u string       Target URL (or pipe via STDIN)\n")
		fmt.Fprintf(os.Stderr, "  -w string       Path to wordlist file\n\n")
		fmt.Fprintf(os.Stderr, "Optional:\n")
		fmt.Fprintf(os.Stderr, "  -t int          Concurrent threads (default: 50)\n")
		fmt.Fprintf(os.Stderr, "  -x string       Extensions (comma-separated)\n")
		fmt.Fprintf(os.Stderr, "  -H string       Custom headers (repeatable)\n")
		fmt.Fprintf(os.Stderr, "  --timeout int   Request timeout in seconds (default: 10)\n")
		fmt.Fprintf(os.Stderr, "  --depth int     Recursive scanning depth (0=disabled)\n")
		fmt.Fprintf(os.Stderr, "  --rate-limit int Max req/s per host (default: 0=unlimited)\n")
		fmt.Fprintf(os.Stderr, "  --retries int   Retry attempts (default: 2)\n")
		fmt.Fprintf(os.Stderr, "  -v              Verbose mode\n")
		fmt.Fprintf(os.Stderr, "  -o string       JSON output file\n")
		fmt.Fprintf(os.Stderr, "  --html string   HTML report file\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  capsaicin -u https://target.com -w wordlist.txt\n")
		fmt.Fprintf(os.Stderr, "  cat targets.txt | capsaicin -w words.txt -t 100\n")
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

	return config
}

func Validate(config *Config, targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	for i := range targets {
		if !strings.HasPrefix(targets[i], "http://") && !strings.HasPrefix(targets[i], "https://") {
			targets[i] = "http://" + targets[i]
		}
	}

	if config.Wordlist == "" {
		return fmt.Errorf("wordlist is required (-w)")
	}

	if _, err := os.Stat(config.Wordlist); os.IsNotExist(err) {
		return fmt.Errorf("wordlist file not found: %s", config.Wordlist)
	}

	return nil
}