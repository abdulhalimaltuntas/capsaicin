package ui

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/scanner"
)

func TestRenderers(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetColorEnabled(false)
	SetSilent(false)
	SetRich(false)

	PrintBanner()
	PrintConfig(config.Config{
		Threads: 10, Timeout: 5, Wordlist: "w.txt", JitterProfile: "moderate",
		MatchCodes: "200-299", FilterCodes: "404", Method: "POST", MaxDepth: 2,
		Extensions: []string{".php"}, Spider: true, ExtractPaths: true, SafeMode: true,
		ForceHTTP2: true, TLSImpersonate: "chrome", RateLimit: 50,
	}, 2, 100)

	stats := scanner.NewStats(10)
	stats.IncrementProcessed()
	stats.IncrementFound()
	stats.IncrementSecrets()
	stats.IncrementWAFHits()
	stats.IncrementErrors()
	results := []scanner.Result{
		{URL: "http://x/a", StatusCode: 200, Severity: "critical"},
		{URL: "http://x/b", StatusCode: 301, Severity: "low"},
		{URL: "http://x/c", StatusCode: 403, Severity: "info"},
	}
	PrintSummary(stats, results)

	out := buf.String()
	for _, want := range []string{"C A P S A I C I N", "scan configuration", "Match Code", "Filter Code", "scan complete", "By Severity", "critical"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected UI output to contain %q", want)
		}
	}
}

func TestSilentSuppressesOutput(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetSilent(true)
	PrintBanner()
	PrintConfig(config.Config{Threads: 1}, 1, 1)
	PrintSummary(scanner.NewStats(1), nil)
	SetSilent(false)
	if buf.Len() != 0 {
		t.Errorf("silent mode should suppress all output, got %q", buf.String())
	}
}

func TestLiveUI_EventAndTicker(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetColorEnabled(false)
	SetSilent(false)

	// Plain mode: consume a result event, then channel close returns.
	SetRich(false)
	ch := make(chan scanner.ScanEvent, 2)
	r := scanner.Result{URL: "http://x/found", StatusCode: 200, SecretFound: true, SecretTypes: []string{"AWS"}, WAFDetected: "Cloudflare", Method: "POST"}
	ch <- scanner.ScanEvent{Type: scanner.EventResultFound, Result: &r}
	ch <- scanner.ScanEvent{Type: scanner.EventURLTrying, URL: "http://x/trying"}
	close(ch)
	StartLiveUI(scanner.NewStats(5), ch, context.Background())
	if !strings.Contains(buf.String(), "http://x/found") {
		t.Error("expected the found URL to be printed")
	}

	// Rich mode: run the animated ticker briefly, then cancel.
	SetRich(true)
	ch2 := make(chan scanner.ScanEvent)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	stats := scanner.NewStats(100)
	stats.IncrementProcessed()
	go func() { StartLiveUI(stats, ch2, ctx); close(done) }()
	time.Sleep(250 * time.Millisecond)
	cancel()
	<-done
	SetRich(false)
}

func TestHelpers(t *testing.T) {
	if formatSize(2*1024*1024) == "" || formatSize(2048) == "" || formatSize(10) == "" {
		t.Error("formatSize should render")
	}
	if fmtDuration(3661) != "1:01:01" {
		t.Errorf("fmtDuration hours wrong: %s", fmtDuration(3661))
	}
	if fmtDuration(65) != "1:05" {
		t.Errorf("fmtDuration mins wrong: %s", fmtDuration(65))
	}
	if fmtDuration(-1) != "--:--" {
		t.Error("fmtDuration should guard negatives")
	}
	if gradientBar(3, 10) == "" {
		t.Error("gradientBar should render")
	}
	for _, c := range []int{200, 301, 404, 500, 100} {
		_ = statusToColor(c)
		_ = statusToBg(c)
	}
}
