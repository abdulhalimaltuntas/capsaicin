package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/scanner"
)

func PrintBanner() {
	fmt.Println("CAPSAICIN v2.0 - Web Directory Scanner")
	fmt.Println("========================================")
}

func PrintConfig(cfg interface{}, targetCount int) {
	fmt.Println("\nScan Configuration:")
	fmt.Printf("  Targets: %d\n", targetCount)
	fmt.Println()
}

func PrintResult(result scanner.Result) {
	var statusColor string
	switch {
	case result.StatusCode >= 200 && result.StatusCode < 300:
		statusColor = "\033[32m"
	case result.StatusCode >= 300 && result.StatusCode < 400:
		statusColor = "\033[34m"
	case result.StatusCode >= 400 && result.StatusCode < 500:
		statusColor = "\033[31m"
	case result.StatusCode >= 500:
		statusColor = "\033[33m"
	default:
		statusColor = "\033[37m"
	}

	reset := "\033[0m"

	badges := []string{}
	if result.Critical {
		badges = append(badges, "[CRITICAL]")
	}
	if result.SecretFound {
		badges = append(badges, fmt.Sprintf("[SECRET:%s]", strings.Join(result.SecretTypes, ",")))
	}
	if result.WAFDetected != "" {
		badges = append(badges, fmt.Sprintf("[WAF:%s]", result.WAFDetected))
	}
	if result.Method != "GET" && result.Method != "GET+BYPASS" {
		badges = append(badges, fmt.Sprintf("[%s]", result.Method))
	}

	badgeStr := ""
	if len(badges) > 0 {
		badgeStr = " " + strings.Join(badges, " ")
	}

	fmt.Printf("%s%d%s | %7db | %s%s\n",
		statusColor, result.StatusCode, reset,
		result.Size,
		result.URL,
		badgeStr)
}

func StartProgressReporter(stats *scanner.Stats, ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Print("\r\033[K")
			return
		case <-ticker.C:
			elapsed := time.Since(stats.StartTime).Seconds()
			reqPerSec := float64(stats.GetProcessed()) / elapsed
			total := stats.GetTotal()
			processed := stats.GetProcessed()
			var progress float64
			if total > 0 {
				progress = float64(processed) / float64(total) * 100
			}

			fmt.Printf("\r[%.1f%%] %d req/s | Found: %d | Secrets: %d | WAF: %d | Errors: %d",
				progress,
				int(reqPerSec),
				stats.GetFound(),
				stats.GetSecrets(),
				stats.GetWAFHits(),
				stats.GetErrors())
		}
	}
}

func PrintSummary(stats *scanner.Stats) {
	elapsed := time.Since(stats.StartTime)
	fmt.Println("\n\nScan Summary:")
	fmt.Println("=============")
	fmt.Printf("Total Requests:  %d\n", stats.GetProcessed())
	fmt.Printf("Findings:        %d\n", stats.GetFound())
	fmt.Printf("Secrets Found:   %d\n", stats.GetSecrets())
	fmt.Printf("WAF Detections:  %d\n", stats.GetWAFHits())
	fmt.Printf("Errors:          %d\n", stats.GetErrors())
	fmt.Printf("Duration:        %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Req/s:           %.2f\n", float64(stats.GetProcessed())/elapsed.Seconds())
}