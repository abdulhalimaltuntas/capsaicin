package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sampleSnapshot() Snapshot {
	return Snapshot{Processed: 42, Total: 100, Found: 7, Errors: 3, Secrets: 2, WAFHits: 1, ElapsedSec: 21}
}

func TestHandleMetricsFormat(t *testing.T) {
	s := New(":0", sampleSnapshot)
	rec := httptest.NewRecorder()
	s.handleMetrics(rec, httptest.NewRequest("GET", "/metrics", nil))

	body := rec.Body.String()
	for _, want := range []string{
		"capsaicin_requests_total 42",
		"capsaicin_findings_total 7",
		"capsaicin_progress_percent 42",
		"capsaicin_requests_per_second 2", // 42/21
		"# TYPE capsaicin_errors_total counter",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("unexpected content-type %q", ct)
	}
}

func TestServerLifecycle(t *testing.T) {
	// Grab a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := New(addr, sampleSnapshot)
	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer s.Stop(context.Background())

	// Give the listener a moment to bind.
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://" + addr + "/metrics")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "capsaicin_requests_total") {
		t.Errorf("unexpected /metrics response: %d %s", resp.StatusCode, string(b))
	}

	health, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer health.Body.Close()
	hb, _ := io.ReadAll(health.Body)
	if strings.TrimSpace(string(hb)) != "ok" {
		t.Errorf("healthz = %q", string(hb))
	}
}
