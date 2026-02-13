package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/scanner"
)

const (
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

	// Cursor / line control
	clearLine = "\033[2K"
	moveUp    = "\033[1A"
)

// PrintBanner displays a clean, professional banner.
func PrintBanner() {
	fmt.Println()
	fmt.Printf("  %s%s┌──────────────────────────────────────────────────┐%s\n", bold, red, reset)
	fmt.Printf("  %s%s│%s  🌶  %s%sCAPSAICIN%s  %sv3.1%s  %s%s─  Web Directory Scanner  %s%s│%s\n",
		bold, red, reset,
		bold, white, reset,
		dim, reset,
		dim, white, reset,
		bold+red, reset)
	fmt.Printf("  %s%s└──────────────────────────────────────────────────┘%s\n", bold, red, reset)
	fmt.Println()
}

// PrintConfig displays scan configuration in a structured panel.
func PrintConfig(cfg config.Config, targetCount int, wordCount int) {
	fmt.Printf("  %s%s⚙  Scan Configuration%s\n", bold, cyan, reset)
	fmt.Printf("  %s──────────────────────────────────────%s\n", dim, reset)
	fmt.Printf("  %s%-14s%s %s%d%s\n", dim, "Targets", reset, white, targetCount, reset)
	fmt.Printf("  %s%-14s%s %s%d%s\n", dim, "Threads", reset, white, cfg.Threads, reset)
	fmt.Printf("  %s%-14s%s %s%ds%s\n", dim, "Timeout", reset, white, cfg.Timeout, reset)
	fmt.Printf("  %s%-14s%s %s%s%s\n", dim, "Wordlist", reset, white, cfg.Wordlist, reset)
	if wordCount > 0 {
		fmt.Printf("  %s%-14s%s %s%d words%s\n", dim, "Words", reset, white, wordCount, reset)
	}

	if cfg.RateLimit > 0 {
		fmt.Printf("  %s%-14s%s %s%d req/s%s\n", dim, "Rate Limit", reset, white, cfg.RateLimit, reset)
	} else {
		fmt.Printf("  %s%-14s%s %sunlimited%s\n", dim, "Rate Limit", reset, dim+white, reset)
	}

	if cfg.MaxDepth > 0 {
		fmt.Printf("  %s%-14s%s %s%d%s\n", dim, "Max Depth", reset, white, cfg.MaxDepth, reset)
	}
	if len(cfg.Extensions) > 0 {
		fmt.Printf("  %s%-14s%s %s%s%s\n", dim, "Extensions", reset, white, strings.Join(cfg.Extensions, ", "), reset)
	}
	if cfg.SafeMode {
		fmt.Printf("  %s%-14s%s %s%s⚠ Safe Mode%s\n", dim, "Mode", reset, bold, yellow, reset)
	}
	fmt.Printf("  %s%-14s%s %s%s%s\n", dim, "Started", reset, white, time.Now().Format("15:04:05 — 2006-01-02"), reset)
	fmt.Printf("  %s──────────────────────────────────────%s\n", dim, reset)
	fmt.Println()
}

// PrintResult formats a single scan result with status badge and tags.
func PrintResult(result scanner.Result) {
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

	if len(result.Technologies) > 0 {
		tags = append(tags, fmt.Sprintf("%s%s[%s]%s", dim, blue, strings.Join(result.Technologies, ", "), reset))
	}

	sizeStr := formatSize(result.Size)

	tagStr := ""
	if len(tags) > 0 {
		tagStr = "  " + strings.Join(tags, " ")
	}

	fmt.Printf("%s  %s%s%s  %s%s%s%s\n",
		badge,
		dim, sizeStr, reset,
		statusColor, result.URL, reset,
		tagStr)
}

// printResultInline prints a result during live scanning with cursor management.
// It clears the progress line, prints the result, then the progress resumes on next tick.
func printResultInline(result *scanner.Result) {
	// Clear current progress line
	fmt.Printf("\r%s", clearLine)

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
	if len(result.Technologies) > 0 {
		tags = append(tags, fmt.Sprintf("%s%s[%s]%s", dim, blue, strings.Join(result.Technologies, ", "), reset))
	}

	sizeStr := formatSize(result.Size)

	tagStr := ""
	if len(tags) > 0 {
		tagStr = "  " + strings.Join(tags, " ")
	}

	fmt.Printf("%s  %s%s%s  %s%s%s%s\n",
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
			fmt.Printf("\r%s", clearLine)
			return

		case event, ok := <-eventCh:
			if !ok {
				// Channel closed — scan complete.
				fmt.Printf("\r%s", clearLine)
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

			barWidth := 20
			filled := int(progress / 100 * float64(barWidth))
			if filled > barWidth {
				filled = barWidth
			}
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

			s := spinner[frame%len(spinner)]
			frame++

			found := stats.GetFound()
			errors := stats.GetErrors()
			secrets := stats.GetSecrets()

			// Build compact metrics
			foundStr := fmt.Sprintf("%s%d%s", green, found, reset)
			extraMetrics := ""
			if secrets > 0 {
				extraMetrics += fmt.Sprintf("  %s🔑%d%s", magenta, secrets, reset)
			}
			if errors > 0 {
				extraMetrics += fmt.Sprintf("  %s✗%d%s", red, errors, reset)
			}

			// Truncate URL for display
			displayURL := lastURL
			if displayURL == "" {
				displayURL = stats.GetCurrentURL()
			}
			maxURLLen := 50
			if len(displayURL) > maxURLLen {
				displayURL = "…" + displayURL[len(displayURL)-maxURLLen+1:]
			}

			// Line 1: Progress bar + metrics
			fmt.Printf("\r%s", clearLine)
			fmt.Printf("  %s%s %s%s%s %s%.0f%%%s  %s%d%s req/s  Found: %s%s  %s%s%s",
				cyan, s,
				dim, bar, reset,
				bold, progress, reset,
				dim, int(reqPerSec), reset,
				foundStr,
				extraMetrics,
				dim, displayURL, reset)
		}
	}
}

// StartProgressReporter is kept for backward compatibility but delegates to
// a simplified version without event channel.
func StartProgressReporter(stats *scanner.Stats, ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	frame := 0

	for {
		select {
		case <-ctx.Done():
			fmt.Print("\r\033[K")
			return
		case <-ticker.C:
			elapsed := time.Since(stats.StartTime).Seconds()
			if elapsed == 0 {
				elapsed = 1
			}
			reqPerSec := float64(stats.GetProcessed()) / elapsed
			total := stats.GetTotal()
			processed := stats.GetProcessed()
			var progress float64
			if total > 0 {
				progress = float64(processed) / float64(total) * 100
			}

			barWidth := 20
			filled := int(progress / 100 * float64(barWidth))
			if filled > barWidth {
				filled = barWidth
			}
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

			s := spinner[frame%len(spinner)]
			frame++

			found := stats.GetFound()
			secrets := stats.GetSecrets()
			wafHits := stats.GetWAFHits()
			errors := stats.GetErrors()

			foundStr := fmt.Sprintf("%s%d%s", green, found, reset)
			secretStr := ""
			if secrets > 0 {
				secretStr = fmt.Sprintf("  %s🔑 %d%s", magenta, secrets, reset)
			}
			wafStr := ""
			if wafHits > 0 {
				wafStr = fmt.Sprintf("  %s🛡 %d%s", yellow, wafHits, reset)
			}
			errStr := ""
			if errors > 0 {
				errStr = fmt.Sprintf("  %s✗ %d%s", red, errors, reset)
			}

			fmt.Printf("\r  %s%s %s%s%s %s%.0f%%%s  %s%d%s req/s  Found: %s%s%s%s",
				cyan, s,
				dim, bar, reset,
				bold, progress, reset,
				dim, int(reqPerSec), reset,
				foundStr,
				secretStr, wafStr, errStr)
		}
	}
}

// PrintSummary displays the final scan summary with actionable metrics.
func PrintSummary(stats *scanner.Stats) {
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

	fmt.Println()
	fmt.Printf("  %s%s✔  Scan Complete%s\n", bold, green, reset)
	fmt.Printf("  %s──────────────────────────────────────%s\n", dim, reset)

	fmt.Printf("  %s%-14s%s %s%d%s\n", dim, "Requests", reset, white, processed, reset)
	fmt.Printf("  %s%-14s%s %s%s%d%s\n", dim, "Findings", reset, bold, green, stats.GetFound(), reset)

	if stats.GetSecrets() > 0 {
		fmt.Printf("  %s%-14s%s %s%s%d%s\n", dim, "Secrets", reset, bold, magenta, stats.GetSecrets(), reset)
	}
	if stats.GetWAFHits() > 0 {
		fmt.Printf("  %s%-14s%s %s%s%d%s\n", dim, "WAF Hits", reset, bold, yellow, stats.GetWAFHits(), reset)
	}
	if errors > 0 {
		fmt.Printf("  %s%-14s%s %s%s%d%s  %s(%.1f%%)%s\n", dim, "Errors", reset, bold, red, errors, reset, dim, errorRate, reset)
	}

	fmt.Printf("  %s%-14s%s %s%s%s\n", dim, "Duration", reset, white, elapsed.Round(time.Millisecond), reset)
	fmt.Printf("  %s%-14s%s %s%.0f req/s%s\n", dim, "Speed", reset, white, reqPerSec, reset)
	fmt.Println()
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
