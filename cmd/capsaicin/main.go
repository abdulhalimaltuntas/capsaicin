package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

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
		fmt.Println("Reading targets from STDIN...")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			target := strings.TrimSpace(sc.Text())
			if target != "" && !strings.HasPrefix(target, "#") {
				targets = append(targets, target)
			}
		}
		fmt.Printf("Loaded %d targets\n", len(targets))
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

	ui.PrintConfig(cfg, len(targets))

	engine := scanner.NewEngine(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("Starting scan...")

	var results []scanner.Result
	var stats *scanner.Stats

	if cfg.Verbose {
		res, st, err := engine.Run(targets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %s\n", err)
			os.Exit(1)
		}
		results = res
		stats = st

		for _, result := range results {
			ui.PrintResult(result)
		}
	} else {
		go func() {
			res, st, err := engine.Run(targets)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Scan error: %s\n", err)
				cancel()
				return
			}
			results = res
			stats = st
			cancel()
		}()

		<-ctx.Done()

		if stats == nil {
			os.Exit(1)
		}
	}

	ui.PrintSummary(stats)

	if cfg.OutputFile != "" {
		if err := reporting.SaveJSON(results, cfg.OutputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save JSON: %s\n", err)
		} else {
			fmt.Printf("\nJSON report saved: %s\n", cfg.OutputFile)
		}
	}

	if cfg.HTMLReport != "" {
		if err := reporting.GenerateHTML(results, cfg.HTMLReport); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate HTML: %s\n", err)
		} else {
			fmt.Printf("HTML report saved: %s\n", cfg.HTMLReport)
		}
	}
}
