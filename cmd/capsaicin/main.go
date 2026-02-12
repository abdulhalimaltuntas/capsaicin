package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/reporting"
	"github.com/capsaicin/scanner/internal/scanner"
	"github.com/capsaicin/scanner/internal/ui"
)

func main() {
	ui.PrintBanner()

	cfg := config.Parse()

	targets := []string{}
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		fmt.Printf("  %sReading targets from STDIN...%s\n", "\033[2m", "\033[0m")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			target := strings.TrimSpace(sc.Text())
			if target != "" && !strings.HasPrefix(target, "#") {
				targets = append(targets, target)
			}
		}
		fmt.Printf("  %sLoaded %d targets%s\n", "\033[2m", len(targets), "\033[0m")
	} else if cfg.TargetURL != "" {
		targets = append(targets, cfg.TargetURL)
	} else {
		fmt.Fprintln(os.Stderr, "Error: No target specified. Use -u flag or pipe targets via STDIN")
		os.Exit(1)
	}

	if err := config.Validate(&cfg, targets); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	// Count wordlist lines for display.
	wordCount, _ := scanner.CountWordlist(cfg.Wordlist)
	ui.PrintConfig(cfg, len(targets), wordCount)

	engine := scanner.NewEngine(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		fmt.Fprintf(os.Stderr, "\n  [!] Received signal %s, shutting down gracefully...\n", sig)
		cancel()
		// Second signal → force exit
		sig = <-sigChan
		fmt.Fprintf(os.Stderr, "\n  [!] Received second signal %s, force exiting...\n", sig)
		os.Exit(1)
	}()

	scanStart := time.Now()
	runID := reporting.GenerateRunID()

	// Event channel for live UI updates.
	eventCh := make(chan scanner.ScanEvent, cfg.Threads*4)

	type scanResult struct {
		results []scanner.Result
		stats   *scanner.Stats
		err     error
	}

	resultCh := make(chan scanResult, 1)

	go func() {
		res, st, err := engine.RunWithEvents(ctx, targets, eventCh)
		resultCh <- scanResult{results: res, stats: st, err: err}
	}()

	// Wait for engine to initialize stats, then start live UI.
	stats := engine.WaitForStatsCtx(ctx)
	if stats == nil {
		fmt.Fprintln(os.Stderr, "  [!] Scan cancelled before initialization")
		os.Exit(0)
	}
	uiCtx, uiCancel := context.WithCancel(ctx)
	uiDone := make(chan struct{})
	go func() {
		ui.StartLiveUI(stats, eventCh, uiCtx)
		close(uiDone)
	}()

	// Wait for scan to complete.
	sr := <-resultCh
	uiCancel()
	<-uiDone // wait for UI to finish

	results := sr.results

	if sr.err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "  [!] Scan cancelled by user")
		} else {
			fmt.Fprintf(os.Stderr, "Scan error: %s\n", sr.err)
			os.Exit(1)
		}
	}

	if stats == nil {
		os.Exit(1)
	}

	ui.PrintSummary(stats)

	if cfg.OutputFile != "" {
		scanDuration := time.Since(scanStart)
		if err := reporting.SaveJSONReport(results, cfg.OutputFile, targets, runID, scanStart, scanDuration); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save JSON: %s\n", err)
		} else {
			fmt.Printf("  JSON report saved: %s\n", cfg.OutputFile)
		}
	}

	if cfg.HTMLReport != "" {
		if err := reporting.GenerateHTML(results, cfg.HTMLReport); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate HTML: %s\n", err)
		} else {
			fmt.Printf("  HTML report saved: %s\n", cfg.HTMLReport)
		}
	}

	if cfg.FailOn != "" {
		exitCode := scanner.DetermineExitCode(results, cfg.FailOn)
		if exitCode != 0 {
			fmt.Fprintf(os.Stderr, "\n  [!] Findings meet --fail-on %s threshold (exit code %d)\n", cfg.FailOn, exitCode)
			os.Exit(exitCode)
		}
	}
}
