package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/abdulhalimaltuntas/capsaicin/internal/config"
	"github.com/abdulhalimaltuntas/capsaicin/internal/logging"
	"github.com/abdulhalimaltuntas/capsaicin/internal/notify"
	"github.com/abdulhalimaltuntas/capsaicin/internal/reporting"
	"github.com/abdulhalimaltuntas/capsaicin/internal/scanner"
	"github.com/abdulhalimaltuntas/capsaicin/internal/ui"
	"github.com/spf13/cobra"
)

// isTTY reports whether f is an interactive terminal (used to gate color and
// the animated progress display).
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

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
	cfg, err := config.LoadConfig(cmd)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Output modes: keep stdout a clean data channel (UI → stderr), and disable
	// color for non-TTY / NO_COLOR / --no-color. Rich progress is off under
	// --silent/--debug/--verbose so it never clobbers logs or piped output.
	logging.Init(cfg.LogLevel, cfg.Debug)
	stderrTTY := isTTY(os.Stderr)
	if cfg.NoColor || os.Getenv("NO_COLOR") != "" || !stderrTTY {
		ui.SetColorEnabled(false)
	}
	ui.SetSilent(cfg.Silent)
	ui.SetRich(stderrTTY && !cfg.Silent && !cfg.Debug && !cfg.Verbose)

	ui.PrintBanner()

	targets := []string{}
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		fmt.Fprintln(os.Stderr, "  reading targets from STDIN...")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			target := strings.TrimSpace(sc.Text())
			if target != "" && !strings.HasPrefix(target, "#") {
				targets = append(targets, target)
			}
		}
		fmt.Fprintf(os.Stderr, "  loaded %d targets\n", len(targets))
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

	// --dry-run shows the resolved scan plan (printed above) and exits without
	// sending a single request.
	if cfg.DryRun {
		fmt.Fprintln(os.Stderr, "  dry run: plan shown above, no requests sent.")
		return nil
	}

	engine, err := scanner.NewEngine(*cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize scan engine: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Global scan deadline. Without this a hung/slow target (or a target that
	// keeps feeding recursive work) can run indefinitely.
	if cfg.MaxDuration > 0 {
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithTimeout(ctx, time.Duration(cfg.MaxDuration)*time.Second)
		defer deadlineCancel()
		fmt.Fprintf(os.Stderr, "  global scan deadline: %ds\n", cfg.MaxDuration)
	}

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

	// Event channel from the engine. When streaming (`-o - --output-format
	// jsonl`), findings are also written to stdout live via a tee.
	engineEvents := make(chan scanner.ScanEvent, cfg.Threads*4)
	streaming := cfg.OutputFile == "-" && cfg.OutputFormat == "jsonl"

	type scanResult struct {
		results []scanner.Result
		stats   *scanner.Stats
		err     error
	}

	resultCh := make(chan scanResult, 1)

	go func() {
		res, st, err := engine.RunWithEvents(ctx, targets, engineEvents)
		resultCh <- scanResult{results: res, stats: st, err: err}
	}()

	// Tee: forward events to the UI while optionally streaming findings to stdout
	// as JSONL. The engine channel is drained unconditionally so the engine never
	// blocks, even after the UI has stopped (cancellation).
	uiEvents := make(chan scanner.ScanEvent, cfg.Threads*4)
	go func() {
		defer close(uiEvents)
		var enc *json.Encoder
		if streaming {
			enc = json.NewEncoder(os.Stdout)
		}
		for ev := range engineEvents {
			if enc != nil && ev.Type == scanner.EventResultFound && ev.Result != nil {
				_ = enc.Encode(ev.Result)
			}
			select {
			case uiEvents <- ev:
			case <-ctx.Done():
			}
		}
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
		ui.StartLiveUI(stats, uiEvents, uiCtx)
		close(uiDone)
	}()

	// Wait for scan to complete.
	sr := <-resultCh
	uiCancel()
	<-uiDone // wait for UI to finish

	results := sr.results

	if sr.err != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			fmt.Fprintln(os.Stderr, "  [!] Scan stopped: global --max-duration deadline reached (partial results below)")
		case ctx.Err() != nil:
			fmt.Fprintln(os.Stderr, "  [!] Scan cancelled by user")
		default:
			return fmt.Errorf("scan error: %w", sr.err)
		}
	}

	if stats == nil {
		os.Exit(1)
	}

	ui.PrintSummary(stats, results)

	if cfg.OutputFile != "" && !streaming {
		scanDuration := time.Since(scanStart)
		var werr error
		switch cfg.OutputFormat {
		case "jsonl":
			werr = reporting.SaveJSONL(results, cfg.OutputFile)
		case "csv":
			werr = reporting.SaveCSV(results, cfg.OutputFile)
		case "html":
			werr = reporting.GenerateHTML(results, cfg.OutputFile)
		case "sarif":
			werr = reporting.SaveSARIF(results, cfg.OutputFile)
		default: // json
			werr = reporting.SaveJSONReport(results, cfg.OutputFile, targets, runID, scanStart, scanDuration)
		}
		// Status goes to stderr so `-o -` keeps stdout a clean data channel.
		if werr != nil {
			fmt.Fprintf(os.Stderr, "  failed to save %s report: %s\n", cfg.OutputFormat, werr)
		} else if cfg.OutputFile != "-" {
			fmt.Fprintf(os.Stderr, "  %s report saved: %s\n", strings.ToUpper(cfg.OutputFormat), cfg.OutputFile)
		}
	}

	if cfg.HTMLReport != "" {
		if err := reporting.GenerateHTML(results, cfg.HTMLReport); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate HTML: %s\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "  HTML report saved: %s\n", cfg.HTMLReport)
		}
	}

	if cfg.Webhook != "" {
		if n, err := notify.SendWebhook(context.Background(), cfg.Webhook, results, cfg.WebhookMinSeverity); err != nil {
			fmt.Fprintf(os.Stderr, "  webhook failed: %s\n", err)
		} else if n > 0 {
			fmt.Fprintf(os.Stderr, "  webhook: notified %d finding(s) >= %s\n", n, cfg.WebhookMinSeverity)
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
