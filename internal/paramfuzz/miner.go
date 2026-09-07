// Package paramfuzz discovers hidden HTTP query parameters a server processes
// but does not advertise — the classic "Arjun" technique. It sends batches of
// candidate parameters carrying a unique canary value, then isolates the ones
// that change the response (reflection, size/word/status divergence) via binary
// search, keeping the request budget logarithmic in the wordlist size.
package paramfuzz

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Observation is a single response summary the miner reasons over.
type Observation struct {
	Status int
	Size   int
	Words  int
	Body   string
}

// ProbeFunc issues a GET for rawURL through the caller's transport and returns a
// summarized observation. Returning an error drops that probe (treated as noise).
type ProbeFunc func(ctx context.Context, rawURL string) (*Observation, error)

// Discovery is a confirmed hidden parameter and why it was flagged.
type Discovery struct {
	Name   string
	Reason string // "reflected" | "status-change" | "size-change"
}

// Miner runs the discovery algorithm against one URL.
type Miner struct {
	Probe     ProbeFunc
	Params    []string      // candidate parameter names
	ChunkSize int           // params per batch request (default 40)
	Budget    time.Duration // wall-clock cap (default 30s)
	rng       *rand.Rand
}

// New builds a Miner with sane defaults.
func New(probe ProbeFunc, params []string) *Miner {
	return &Miner{
		Probe:     probe,
		Params:    params,
		ChunkSize: 40,
		Budget:    30 * time.Second,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// canary returns an unlikely-to-collide marker value used to spot reflection.
func (m *Miner) canary() string {
	return "cpsn" + strconv.FormatInt(m.rng.Int63(), 36)
}

// Mine returns the hidden parameters discovered on targetURL. It is best-effort:
// probe failures shrink coverage but never abort the run.
func (m *Miner) Mine(ctx context.Context, targetURL string) ([]Discovery, error) {
	if m.Probe == nil || len(m.Params) == 0 {
		return nil, nil
	}
	chunkSize := m.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 40
	}
	budget := m.Budget
	if budget <= 0 {
		budget = 30 * time.Second
	}
	deadline := time.Now().Add(budget)

	base, err := m.Probe(ctx, targetURL)
	if err != nil || base == nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var found []Discovery
	record := func(name, reason string) {
		if seen[name] {
			return
		}
		seen[name] = true
		found = append(found, Discovery{Name: name, Reason: reason})
	}

	for start := 0; start < len(m.Params); start += chunkSize {
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return found, ctx.Err()
		default:
		}
		end := start + chunkSize
		if end > len(m.Params) {
			end = len(m.Params)
		}
		m.bisect(ctx, targetURL, base, m.Params[start:end], record, deadline)
	}
	return found, nil
}

// bisect tests a group of parameters in one request; if the response diverges
// from baseline it recursively halves the group to isolate the responsible
// parameter(s), giving O(k·log n) requests for k real params.
func (m *Miner) bisect(ctx context.Context, targetURL string, base *Observation, group []string, record func(name, reason string), deadline time.Time) {
	if len(group) == 0 || time.Now().After(deadline) {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
	}

	canary := m.canary()
	probeURL, err := withParams(targetURL, group, canary)
	if err != nil {
		return
	}
	obs, err := m.Probe(ctx, probeURL)
	if err != nil || obs == nil {
		return
	}

	reflected := strings.Contains(obs.Body, canary)
	diverged := reflected ||
		obs.Status != base.Status ||
		absInt(obs.Size-base.Size) > sizeTolerance(base.Size) ||
		absInt(obs.Words-base.Words) > 2

	if !diverged {
		return
	}

	// Single parameter isolated: classify why it diverged.
	if len(group) == 1 {
		reason := "size-change"
		switch {
		case reflected:
			reason = "reflected"
		case obs.Status != base.Status:
			reason = "status-change"
		}
		record(group[0], reason)
		return
	}

	mid := len(group) / 2
	m.bisect(ctx, targetURL, base, group[:mid], record, deadline)
	m.bisect(ctx, targetURL, base, group[mid:], record, deadline)
}

// withParams returns targetURL with each name=value pair merged into its query
// string, preserving any pre-existing query parameters.
func withParams(targetURL string, names []string, value string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("parse target: %w", err)
	}
	q := u.Query()
	for _, n := range names {
		q.Set(n, value)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// sizeTolerance scales the acceptable byte delta with the baseline size so large
// dynamic pages (timestamps, CSRF tokens) do not trigger false positives.
func sizeTolerance(base int) int {
	t := base / 50 // 2%
	if t < 24 {
		t = 24
	}
	return t
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
