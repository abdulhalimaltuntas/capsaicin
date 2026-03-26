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

	"github.com/spf13/cobra"
	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/reporting"
	"github.com/capsaicin/scanner/internal/scanner"
	"github.com/capsaicin/scanner/internal/ui"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "capsaicin",
		Short: "Next-Generation Directory & Asset Discovery Engine",
		Long: `Capsaicin v2 — Fast, intelligent web directory scanner built for security professionals.
Features smart anomaly detection, stateful fuzzing, and advanced evasion mechanics.

Examples:
  capsaicin -u https://target.com -w wordlist.txt
  capsaicin -u https://api.target.com/FUZZ -w words.txt --mode dynamic
  cat targets.txt | capsaicin -w words.txt -t 100 --h3 --tls-impersonate chrome`,
		RunE: runScan,
		// Silence errors/usage because we handle printing them explicitly.
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	config.InitFlags(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	ui.PrintBanner()

	cfg, err := config.LoadConfig(cmd)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

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
		return fmt.Errorf("no target specified. Use -u flag or pipe targets via STDIN")
	}

	if err := config.Validate(cfg, targets); err != nil {
		return err
	}

	// Count wordlist lines for display.
	wordCount, _ := scanner.CountWordlist(cfg.Wordlist)
	
	// Value semantic pass for backward-compatibility with UI package which
	// currently expects a non-pointer config.Config struct.
	ui.PrintConfig(*cfg, len(targets), wordCount)

	engine, err := scanner.NewEngine(*cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize scan engine: %w", err)
	}
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
			return fmt.Errorf("scan error: %w", sr.err)
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

	return nil
}
