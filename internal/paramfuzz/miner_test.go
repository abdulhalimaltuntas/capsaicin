package paramfuzz

import (
	"context"
	"net/url"
	"strconv"
	"testing"
)

// buildParams returns a candidate list with a couple of "real" params buried
// among many decoys, to exercise the binary-search isolation.
func buildParams(real ...string) []string {
	params := append([]string{}, real...)
	for i := 0; i < 60; i++ {
		params = append(params, "decoy"+strconv.Itoa(i))
	}
	return params
}

func TestMineReflectedParam(t *testing.T) {
	// The server reflects the value of the "admin" param into the body.
	probe := func(_ context.Context, raw string) (*Observation, error) {
		u, _ := url.Parse(raw)
		q := u.Query()
		body := "baseline content here"
		if v := q.Get("admin"); v != "" {
			body += " reflected=" + v
		}
		return &Observation{Status: 200, Size: len(body), Words: len(body) / 5, Body: body}, nil
	}

	miner := New(probe, buildParams("admin"))
	found, err := miner.Mine(context.Background(), "https://target/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Name != "admin" {
		t.Fatalf("expected to discover 'admin', got %+v", found)
	}
	if found[0].Reason != "reflected" {
		t.Errorf("expected reason 'reflected', got %q", found[0].Reason)
	}
}

func TestMineStatusChangeParam(t *testing.T) {
	// The "debug" param flips the status code.
	probe := func(_ context.Context, raw string) (*Observation, error) {
		u, _ := url.Parse(raw)
		if u.Query().Get("debug") != "" {
			return &Observation{Status: 500, Size: 20, Words: 4, Body: "error"}, nil
		}
		return &Observation{Status: 200, Size: 20, Words: 4, Body: "okok"}, nil
	}

	miner := New(probe, buildParams("debug"))
	found, err := miner.Mine(context.Background(), "https://target/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Name != "debug" || found[0].Reason != "status-change" {
		t.Fatalf("expected debug/status-change, got %+v", found)
	}
}

func TestMineNoHiddenParams(t *testing.T) {
	// Baseline never changes regardless of params → nothing discovered.
	probe := func(_ context.Context, _ string) (*Observation, error) {
		return &Observation{Status: 200, Size: 100, Words: 20, Body: "static body unchanged"}, nil
	}
	miner := New(probe, buildParams())
	found, err := miner.Mine(context.Background(), "https://target/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("expected no discoveries, got %+v", found)
	}
}

func TestMineNilProbe(t *testing.T) {
	m := New(nil, []string{"a"})
	if got, _ := m.Mine(context.Background(), "https://x"); got != nil {
		t.Error("nil probe should yield nil")
	}
}

func TestWithParams(t *testing.T) {
	out, err := withParams("https://h/p?existing=1", []string{"a", "b"}, "X")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(out)
	q := u.Query()
	if q.Get("existing") != "1" || q.Get("a") != "X" || q.Get("b") != "X" {
		t.Errorf("withParams merged incorrectly: %s", out)
	}
}
