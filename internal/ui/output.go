package ui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/scanner"
)

// Cursor / line control (never suppressed — needed even without color).
const (
	clearLine = "\033[2K"
	moveUp    = "\033[1A"
)

// Color codes are vars so SetColorEnabled(false) can blank them for non-TTY
// output, NO_COLOR, or --no-color.
var (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	italic = "\033[3m"

	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"

	bgRed     = "\033[41m"
	bgGreen   = "\033[42m"
	bgYellow  = "\033[43m"
	bgBlue    = "\033[44m"
	bgMagenta = "\033[45m"
	bgCyan    = "\033[46m"

	colorEnabled = true

	// out is where all human-facing UI (banner, config, progress, live results)
	// is written. It defaults to stderr so stdout stays a clean data channel
	// (e.g. `-o -` JSONL) that can be piped to other tools.
	out io.Writer = os.Stderr
)

// SetOutput redirects all UI writes (default: stderr).
func SetOutput(w io.Writer) { out = w }

// SetColorEnabled toggles ANSI styling. When off, every color/style code is
// blanked so piped or redirected output is plain text.
func SetColorEnabled(on bool) {
	colorEnabled = on
	if on {
		return
	}
	reset, bold, dim, italic = "", "", "", ""
	red, green, yellow, blue, magenta, cyan, white = "", "", "", "", "", "", ""
	bgRed, bgGreen, bgYellow, bgBlue, bgMagenta, bgCyan = "", "", "", "", "", ""
}

// richUI enables the animated progress line (spinner/bar/ETA). It is turned off
// for non-TTY output and for --debug/--verbose so logs are not clobbered. silent
// suppresses all human-facing output (banner/config/results/summary).
var (
	richUI = true
	silent = false
)

// SetRich toggles the animated live progress display.
func SetRich(on bool) { richUI = on }

// SetSilent suppresses all UI output (results still go to -o/stdout).
func SetSilent(on bool) { silent = on }

// flame is a red→orange→yellow 256-color ramp evoking chili heat, used to tint
// the banner, rules, and progress bar.
var flame = []int{196, 202, 208, 214, 220, 226}

func fg256(c int) string {
	if !colorEnabled {
		return ""
	}
	return fmt.Sprintf("\033[38;5;%dm", c)
}

// gradient tints a string across the flame ramp, one step per rune.
func gradient(s string) string {
	runes := []rune(s)
	n := len(runes)
	var b strings.Builder
	for i, r := range runes {
		idx := 0
		if n > 1 {
			idx = i * (len(flame) - 1) / (n - 1)
		}
		b.WriteString(fg256(flame[idx]))
		b.WriteRune(r)
	}
	b.WriteString(reset)
	return b.String()
}

// PrintBanner displays the chili-gradient wordmark banner.
func PrintBanner() {
	if silent {
		return
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "   🌶  %s%s%s\n", bold, gradient("C A P S A I C I N"), reset)
	fmt.Fprintf(out, "   %s\n", gradient(strings.Repeat("▔", 34)))
	fmt.Fprintf(out, "   %sweb content discovery%s  %s·%s  %s%sv3.1%s  %s·%s  %s\n",
		dim, reset,
		fg256(208), reset,
		bold, white, reset,
		fg256(208), reset,
		gradient("fast · adaptive · evasive"))
	fmt.Fprintln(out)
}

// row prints one aligned key/value line in the config/summary panels.
func row(label, valueColor, value string) {
	fmt.Fprintf(out, "  %s%-13s%s %s%s%s\n", dim, label, reset, valueColor, value, reset)
}

// chip renders a small highlighted feature tag.
func chip(label string) string {
	return fmt.Sprintf("%s %s %s", fg256(208)+"\033[48;5;236m"+bold, label, reset)
}

// PrintConfig displays scan configuration in a structured panel.
func PrintConfig(cfg config.Config, targetCount int, wordCount int) {
	if silent {
		return
	}
	fmt.Fprintf(out, "  %s%s⚙  scan configuration%s\n", bold, fg256(208), reset)
	fmt.Fprintf(out, "  %s\n", gradient(strings.Repeat("─", 38)))

	row("Targets", white, fmt.Sprintf("%d", targetCount))
	row("Wordlist", white, cfg.Wordlist)
	if wordCount > 0 {
		row("Words", white, fmt.Sprintf("%d", wordCount))
	}
	if len(cfg.Extensions) > 0 {
		row("Extensions", white, strings.Join(cfg.Extensions, ", "))
	}
	if cfg.Method != "" && cfg.Method != "GET" {
		row("Method", cyan+bold, cfg.Method)
	}

	row("Threads", white, fmt.Sprintf("%d", cfg.Threads))
	if cfg.RateLimit > 0 {
		row("Rate Limit", white, fmt.Sprintf("%d req/s", cfg.RateLimit))
	} else {
		row("Rate Limit", dim+white, "unlimited")
	}
	row("Timeout", white, fmt.Sprintf("%ds", cfg.Timeout))

	// Transport: the historically fragile knob — make it explicit.
	transport := "HTTP/1.1+2 (auto)"
	if cfg.EnableHTTP3 {
		transport = "HTTP/3 (QUIC)"
	} else if cfg.ForceHTTP2 {
		transport = "uTLS h2 [" + cfg.TLSImpersonate + "]"
	}
	row("Transport", white, transport)
	row("Jitter", white, cfg.JitterProfile)
	if cfg.MaxDepth > 0 {
		row("Max Depth", white, fmt.Sprintf("%d", cfg.MaxDepth))
	}

	// Matchers / filters — only show what is actually set.
	if cfg.MatchCodes != "" {
		row("Match Code", green, cfg.MatchCodes)
	}
	printFilterRows(cfg)

	// Enabled subsystems as chips.
	var chips []string
	if cfg.Spider {
		chips = append(chips, chip("spider"))
	}
	if cfg.ExtractPaths {
		chips = append(chips, chip("extract"))
	}
	if cfg.AdaptiveRate {
		chips = append(chips, chip("adaptive"))
	}
	if cfg.Headless {
		chips = append(chips, chip("headless"))
	}
	if cfg.AutoCalibrate {
		chips = append(chips, chip("auto-cal"))
	}
	if cfg.SafeMode {
		chips = append(chips, chip("safe"))
	}
	if len(chips) > 0 {
		fmt.Fprintf(out, "  %s%-13s%s %s\n", dim, "Features", reset, strings.Join(chips, " "))
	}

	row("Started", white, time.Now().Format("15:04:05 · 2006-01-02"))
	fmt.Fprintf(out, "  %s\n", gradient(strings.Repeat("─", 38)))
	fmt.Fprintln(out)
}

// printFilterRows renders any active match-size/regex and filter rows.
func printFilterRows(cfg config.Config) {
	if cfg.MatchSize != "" {
		row("Match Size", green, cfg.MatchSize)
	}
	if cfg.MatchRegex != "" {
		row("Match Regex", green, cfg.MatchRegex)
	}
	if cfg.FilterCodes != "" {
		row("Filter Code", yellow, cfg.FilterCodes)
	}
	if cfg.FilterSize != "" {
		row("Filter Size", yellow, cfg.FilterSize)
	}
	if cfg.FilterWords != "" {
		row("Filter Words", yellow, cfg.FilterWords)
	}
}

// printResultInline prints a result during live scanning with cursor management.
// It clears the progress line, prints the result, then the progress resumes on next tick.
func printResultInline(result *scanner.Result) {
	if silent {
		return
	}
	// Clear the animated progress line before printing (rich mode only).
	if richUI {
		fmt.Fprintf(out, "\r%s", clearLine)
	}

	statusColor := statusToColor(result.StatusCode)
	statusBg := statusToBg(result.StatusCode)

	badge := fmt.Sprintf(" %s%s %d %s", bold, statusBg, result.StatusCode, reset)

	var tags []string
	if result.Critical {
		tags = append(tags, fmt.Sprintf("%s%s CRITICAL %s", bold, bgRed, reset))
	}
	if result.SecretFound {
		tags = append(tags, fmt.Sprintf("%s%s 🔑 SECRET %s", bold, bgMagenta, reset))
	}
	if result.WAFDetected != "" {
		tags = append(tags, fmt.Sprintf("%s%s 🛡 %s %s", bold, bgYellow, result.WAFDetected, reset))
	}
	if result.Method != "GET" {
		tags = append(tags, fmt.Sprintf("%s%s%s%s", dim, cyan, result.Method, reset))
	}

	sizeStr := formatSize(result.Size)

	tagStr := ""
	if len(tags) > 0 {
		tagStr = "  " + strings.Join(tags, " ")
	}

	fmt.Fprintf(out, "%s  %s%s%s  %s%s%s%s\n",
		badge,
		dim, sizeStr, reset,
		statusColor, result.URL, reset,
		tagStr)
}

// StartLiveUI is the main UI loop during scanning. It consumes scan events to:
// - Display live progress (spinner, progress bar, req/s, current URL)
// - Print non-404 results inline as they are found
// It replaces the old StartProgressReporter.
func StartLiveUI(stats *scanner.Stats, eventCh <-chan scanner.ScanEvent, ctx context.Context) {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	frame := 0
	lastURL := ""

	for {
		select {
		case <-ctx.Done():
			if richUI {
				fmt.Fprintf(out, "\r%s", clearLine)
			}
			return

		case event, ok := <-eventCh:
			if !ok {
				// Channel closed — scan complete.
				if richUI {
					fmt.Fprintf(out, "\r%s", clearLine)
				}
				return
			}

			switch event.Type {
			case scanner.EventResultFound:
				if event.Result != nil {
					printResultInline(event.Result)
				}
			case scanner.EventURLTrying:
				lastURL = event.URL
			}

		case <-ticker.C:
			if !richUI {
				continue // no animated progress line in plain/silent/non-TTY mode
			}
			elapsed := time.Since(stats.StartTime).Seconds()
			if elapsed == 0 {
				elapsed = 1
			}
			processed := stats.GetProcessed()
			reqPerSec := float64(processed) / elapsed
			total := stats.GetTotal()
			var progress float64
			if total > 0 {
				progress = float64(processed) / float64(total) * 100
			}

			barWidth := 22
			filled := int(progress / 100 * float64(barWidth))
			if filled > barWidth {
				filled = barWidth
			}
			bar := gradientBar(filled, barWidth)

			s := spinner[frame%len(spinner)]
			frame++

			found := stats.GetFound()
			errors := stats.GetErrors()
			secrets := stats.GetSecrets()

			// Build compact metrics
			foundStr := fmt.Sprintf("%s%s%d%s", bold, green, found, reset)
			extraMetrics := ""
			if secrets > 0 {
				extraMetrics += fmt.Sprintf("  %s🔑%d%s", magenta, secrets, reset)
			}
			if errors > 0 {
				extraMetrics += fmt.Sprintf("  %s✗%d%s", red, errors, reset)
			}

			// ETA from current throughput.
			eta := "--:--"
			if reqPerSec > 0 && total > processed {
				eta = fmtDuration(float64(total-processed) / reqPerSec)
			}

			// Truncate URL for display
			displayURL := lastURL
			if displayURL == "" {
				displayURL = stats.GetCurrentURL()
			}
			maxURLLen := 42
			if len(displayURL) > maxURLLen {
				displayURL = "…" + displayURL[len(displayURL)-maxURLLen+1:]
			}

			// Live status line: spinner · bar · pct · rate · eta · metrics · url
			fmt.Fprintf(out, "\r%s", clearLine)
			fmt.Fprintf(out, "  %s%s%s %s %s%3.0f%%%s  %s%d/s%s  %seta %s%s  %s  %s%s%s",
				fg256(208), s, reset,
				bar,
				bold, progress, reset,
				cyan, int(reqPerSec), reset,
				dim, eta, reset,
				foundStr+extraMetrics,
				dim, displayURL, reset)
		}
	}
}

// PrintSummary displays the final scan summary with actionable metrics and a
// severity breakdown of the findings.
func PrintSummary(stats *scanner.Stats, results []scanner.Result) {
	if silent {
		return
	}
	elapsed := time.Since(stats.StartTime)
	processed := stats.GetProcessed()
	var reqPerSec float64
	if elapsed.Seconds() > 0 {
		reqPerSec = float64(processed) / elapsed.Seconds()
	}

	errors := stats.GetErrors()
	var errorRate float64
	if processed > 0 {
		errorRate = float64(errors) / float64(processed) * 100
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %s%s✔  scan complete%s\n", bold, green, reset)
	fmt.Fprintf(out, "  %s\n", gradient(strings.Repeat("─", 38)))

	row("Requests", white, fmt.Sprintf("%d", processed))
	fmt.Fprintf(out, "  %s%-13s%s %s%s%d%s\n", dim, "Findings", reset, bold, green, stats.GetFound(), reset)

	// Severity breakdown from the deduplicated result set.
	if line := severityBreakdown(results); line != "" {
		fmt.Fprintf(out, "  %s%-13s%s %s\n", dim, "By Severity", reset, line)
	}

	if stats.GetSecrets() > 0 {
		fmt.Fprintf(out, "  %s%-13s%s %s%s%d%s\n", dim, "Secrets", reset, bold, magenta, stats.GetSecrets(), reset)
	}
	if stats.GetWAFHits() > 0 {
		fmt.Fprintf(out, "  %s%-13s%s %s%s%d%s\n", dim, "WAF Hits", reset, bold, yellow, stats.GetWAFHits(), reset)
	}
	if errors > 0 {
		fmt.Fprintf(out, "  %s%-13s%s %s%s%d%s  %s(%.1f%%)%s\n", dim, "Errors", reset, bold, red, errors, reset, dim, errorRate, reset)
	}

	row("Duration", white, elapsed.Round(time.Millisecond).String())
	row("Speed", white, fmt.Sprintf("%.0f req/s", reqPerSec))
	fmt.Fprintf(out, "  %s\n", gradient(strings.Repeat("─", 38)))
	fmt.Fprintln(out)
}

// severityBreakdown returns a compact colored tally like
// "2 critical · 1 high · 5 low", omitting zero buckets.
func severityBreakdown(results []scanner.Result) string {
	counts := map[string]int{}
	for i := range results {
		counts[results[i].Severity]++
	}
	order := []struct {
		key, label, color string
	}{
		{scanner.SeverityCritical, "critical", red + bold},
		{scanner.SeverityHigh, "high", fg256(208) + bold},
		{scanner.SeverityMedium, "medium", yellow},
		{scanner.SeverityLow, "low", blue},
		{scanner.SeverityInfo, "info", dim + white},
	}
	var parts []string
	for _, o := range order {
		if n := counts[o.key]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s%d %s%s", o.color, n, o.label, reset))
		}
	}
	return strings.Join(parts, dim+" · "+reset)
}

func statusToColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return green
	case code >= 300 && code < 400:
		return blue
	case code >= 400 && code < 500:
		return red
	case code >= 500:
		return yellow
	default:
		return white
	}
}

func statusToBg(code int) string {
	switch {
	case code >= 200 && code < 300:
		return bgGreen
	case code >= 300 && code < 400:
		return bgBlue
	case code >= 400 && code < 500:
		return bgRed
	case code >= 500:
		return bgYellow
	default:
		return ""
	}
}

func formatSize(bytes int) string {
	switch {
	case bytes >= 1024*1024:
		return fmt.Sprintf("%5.1fMB", float64(bytes)/1024/1024)
	case bytes >= 1024:
		return fmt.Sprintf("%5.1fKB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%6dB", bytes)
	}
}

// gradientBar renders a progress bar whose filled portion is tinted across the
// flame ramp and whose remainder is dimmed.
func gradientBar(filled, width int) string {
	var b strings.Builder
	for i := 0; i < width; i++ {
		if i < filled {
			idx := 0
			if width > 1 {
				idx = i * (len(flame) - 1) / (width - 1)
			}
			b.WriteString(fg256(flame[idx]))
			b.WriteString("█")
		} else {
			b.WriteString(dim + "░")
		}
	}
	b.WriteString(reset)
	return b.String()
}

// fmtDuration renders a seconds count as m:ss (or h:mm:ss for long scans).
func fmtDuration(seconds float64) string {
	if seconds < 0 || seconds > 359999 {
		return "--:--"
	}
	s := int(seconds)
	h, m, sec := s/3600, (s%3600)/60, s%60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, sec)
	}
	return fmt.Sprintf("%d:%02d", m, sec)
}
