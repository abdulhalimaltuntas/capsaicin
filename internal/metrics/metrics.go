// Package metrics exposes live scan telemetry in Prometheus text-exposition
// format over HTTP, so long-running scans can be scraped by Prometheus/Grafana.
// It is dependency-free: the exposition format is emitted by hand.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Snapshot is a point-in-time view of scan progress. The caller supplies a
// closure that reads it from the live Stats, keeping this package decoupled from
// the scanner.
type Snapshot struct {
	Processed  int64
	Total      int64
	Found      int64
	Errors     int64
	Secrets    int64
	WAFHits    int64
	ElapsedSec float64
}

// Server serves /metrics and /healthz.
type Server struct {
	addr     string
	snapshot func() Snapshot
	srv      *http.Server
}

// New builds a metrics server bound to addr (e.g. ":9090"), reading state via
// snapshot.
func New(addr string, snapshot func() Snapshot) *Server {
	return &Server{addr: addr, snapshot: snapshot}
}

// Start begins serving in a background goroutine and returns immediately. Any
// listen error is returned synchronously.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	s.srv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = s.srv.ListenAndServe() }()
	return nil
}

// Stop gracefully shuts the server down.
func (s *Server) Stop(ctx context.Context) {
	if s.srv != nil {
		_ = s.srv.Shutdown(ctx)
	}
}

// handleMetrics renders the current snapshot in Prometheus exposition format.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	var b strings.Builder
	metric := func(name, help, typ string, value float64) {
		fmt.Fprintf(&b, "# HELP capsaicin_%s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE capsaicin_%s %s\n", name, typ)
		fmt.Fprintf(&b, "capsaicin_%s %g\n", name, value)
	}

	metric("requests_total", "Requests processed so far.", "counter", float64(snap.Processed))
	metric("requests_planned", "Total requests planned (denominator).", "gauge", float64(snap.Total))
	metric("findings_total", "Findings surfaced so far.", "counter", float64(snap.Found))
	metric("errors_total", "Request errors so far.", "counter", float64(snap.Errors))
	metric("secrets_total", "Secrets detected so far.", "counter", float64(snap.Secrets))
	metric("waf_hits_total", "WAF detections so far.", "counter", float64(snap.WAFHits))
	metric("elapsed_seconds", "Seconds since the scan started.", "gauge", snap.ElapsedSec)

	var rps float64
	if snap.ElapsedSec > 0 {
		rps = float64(snap.Processed) / snap.ElapsedSec
	}
	metric("requests_per_second", "Current request throughput.", "gauge", rps)

	var progress float64
	if snap.Total > 0 {
		progress = float64(snap.Processed) / float64(snap.Total) * 100
	}
	metric("progress_percent", "Scan completion percentage.", "gauge", progress)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(b.String()))
}
