package detection

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

// ResponseSignature captures the measurable fingerprint of an HTTP response.
// Two responses with identical signatures are considered "the same page".
type ResponseSignature struct {
	StatusCode int
	Size       int
	WordCount  int
	LineCount  int
	SimHash    uint64 // Charikar SimHash of the body for near-duplicate matching.
}

// signatureKey is a composite hash key for O(1) map lookups.
// Format: "statusCode:size:wordCount:lineCount"
type signatureKey string

func makeKey(statusCode, size, wordCount, lineCount int) signatureKey {
	return signatureKey(fmt.Sprintf("%d:%d:%d:%d", statusCode, size, wordCount, lineCount))
}

func (s *ResponseSignature) key() signatureKey {
	return makeKey(s.StatusCode, s.Size, s.WordCount, s.LineCount)
}

// ────────────────────────────────────────────────────────────────────────────
// Baseline — The result of calibration for a single host
// ────────────────────────────────────────────────────────────────────────────

// Baseline holds the calibrated "noise" fingerprints for a target.
// It supports two matching strategies:
//   - Exact:    O(1) map lookup for fully static error pages
//   - Tolerant: fuzzy range match for dynamic pages (timestamps, IDs)
type Baseline struct {
	// exactSet is the primary O(1) lookup for strict matches.
	exactSet map[signatureKey]struct{}

	// tolerantRanges are used when calibration probes returned varying sizes,
	// indicating a dynamic page. We store [min, max] bounds for each metric.
	tolerantRanges []tolerantRange

	// isDynamic is true when the calibration probes showed variance,
	// meaning the target embeds timestamps, request IDs, or nonces.
	isDynamic bool

	// probes retains the raw calibration signatures (including body SimHash)
	// so responses can be matched by near-duplicate body similarity even when
	// their size/word/line counts fall outside the exact and tolerant checks.
	probes []ResponseSignature
}

// tolerantRange stores the observed minimum and maximum values from
// calibration probes for fuzzy matching.
type tolerantRange struct {
	StatusCode int
	MinSize    int
	MaxSize    int
	MinWords   int
	MaxWords   int
	MinLines   int
	MaxLines   int
}

// ────────────────────────────────────────────────────────────────────────────
// CalibrationCache — Thread-safe per-host baseline cache
// ────────────────────────────────────────────────────────────────────────────

// CalibrationCache stores calibration baselines per target URL.
type CalibrationCache struct {
	mu        sync.RWMutex
	baselines map[string]*Baseline

	// Legacy field kept for backward compatibility with existing callers.
	signatures map[string][]ResponseSignature
}

// NewCalibrationCache creates a new cache.
func NewCalibrationCache() *CalibrationCache {
	return &CalibrationCache{
		baselines:  make(map[string]*Baseline),
		signatures: make(map[string][]ResponseSignature),
	}
}

// Get returns legacy signatures for backward compatibility.
func (c *CalibrationCache) Get(targetURL string) ([]ResponseSignature, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sigs, ok := c.signatures[targetURL]
	return sigs, ok
}

// Set stores legacy signatures for backward compatibility.
func (c *CalibrationCache) Set(targetURL string, sigs []ResponseSignature) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.signatures[targetURL] = sigs
}

// GetBaseline returns the advanced calibration baseline for a host.
func (c *CalibrationCache) GetBaseline(targetURL string) (*Baseline, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	b, ok := c.baselines[targetURL]
	return b, ok
}

// SetBaseline stores an advanced calibration baseline.
func (c *CalibrationCache) SetBaseline(targetURL string, b *Baseline) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baselines[targetURL] = b
}

// ────────────────────────────────────────────────────────────────────────────
// Calibration Probing — PHASE 1: Baseline Generation
// ────────────────────────────────────────────────────────────────────────────

const calibrationProbeCount = 5

// calibrationMaxBodyBytes caps how much of each calibration probe response is
// read for fingerprinting. 8 MiB is far larger than any real error page while
// still bounding memory for pathological targets.
const calibrationMaxBodyBytes = 8 << 20

var calRng = struct {
	mu  sync.Mutex
	rng *rand.Rand
}{
	rng: rand.New(rand.NewSource(time.Now().UnixNano())),
}

func calRandIntn(n int) int {
	calRng.mu.Lock()
	defer calRng.mu.Unlock()
	return calRng.rng.Intn(n)
}

// Fetcher issues a request and returns the response plus its already-read,
// size-bounded body. It lets calibration reuse the scanner's transport pipeline
// (rate limiting, circuit breaker, jitter, uTLS) instead of a bare http.Client,
// keeping evasion and pacing consistent across every request the tool makes.
type Fetcher func(ctx context.Context, req *http.Request) (*http.Response, []byte, error)

// ClientFetcher adapts a plain *http.Client into a Fetcher (used by tests and
// any caller without the full transport client).
func ClientFetcher(c *http.Client) Fetcher {
	return func(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
		resp, err := c.Do(req.WithContext(ctx))
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, calibrationMaxBodyBytes))
		if err != nil {
			return resp, nil, err
		}
		return resp, body, nil
	}
}

// PerformCalibration sends 5 random probes to the target, fingerprints each
// response, and builds a Baseline that supports both exact O(1) and tolerant
// matching. This MUST be called before scanning begins for each target.
func PerformCalibration(ctx context.Context, targetURL string, fetch Fetcher, headers map[string]string, cache *CalibrationCache) []ResponseSignature {
	// Early return if already calibrated.
	if sigs, ok := cache.Get(targetURL); ok {
		return sigs
	}

	// Phase 1: Generate unique probe paths.
	probePaths := make([]string, calibrationProbeCount)
	for i := range probePaths {
		probePaths[i] = fmt.Sprintf("/capsaicin_cal_%d_%d", calRandIntn(999999), i)
	}

	// Phase 2: Fetch signatures from all probes.
	signatures := make([]ResponseSignature, 0, calibrationProbeCount)
	for _, path := range probePaths {
		select {
		case <-ctx.Done():
			return signatures
		default:
		}
		url := calibrationURL(targetURL, path)
		sig := fetchSignature(ctx, url, fetch, headers)
		if sig != nil {
			signatures = append(signatures, *sig)
		}
	}

	if len(signatures) == 0 {
		cache.Set(targetURL, signatures)
		return signatures
	}

	// Phase 3: Analyze probe results and build baseline.
	baseline := buildBaseline(signatures)
	cache.Set(targetURL, signatures)
	cache.SetBaseline(targetURL, baseline)

	return signatures
}

// Recalibrate re-probes a target and overwrites its cached baseline, ignoring
// the "already calibrated" short-circuit. It is used for rolling recalibration
// so long scans adapt to backends whose error pages drift over time.
func Recalibrate(ctx context.Context, targetURL string, fetch Fetcher, headers map[string]string, cache *CalibrationCache) {
	probePaths := make([]string, calibrationProbeCount)
	for i := range probePaths {
		probePaths[i] = fmt.Sprintf("/capsaicin_recal_%d_%d", calRandIntn(999999), i)
	}

	signatures := make([]ResponseSignature, 0, calibrationProbeCount)
	for _, path := range probePaths {
		select {
		case <-ctx.Done():
			return
		default:
		}
		sig := fetchSignature(ctx, calibrationURL(targetURL, path), fetch, headers)
		if sig != nil {
			signatures = append(signatures, *sig)
		}
	}

	if len(signatures) == 0 {
		return
	}
	cache.Set(targetURL, signatures)
	cache.SetBaseline(targetURL, buildBaseline(signatures))
}

// ────────────────────────────────────────────────────────────────────────────
// Baseline Construction — PHASE 2: Fingerprinting + Anomaly Detection
// ────────────────────────────────────────────────────────────────────────────

// buildBaseline analyzes the collected probe signatures and constructs
// a Baseline with the appropriate matching strategy.
func buildBaseline(sigs []ResponseSignature) *Baseline {
	b := &Baseline{
		exactSet: make(map[signatureKey]struct{}),
		probes:   sigs,
	}

	// First, check if all probes returned identical signatures (static page).
	allIdentical := true
	for i := 1; i < len(sigs); i++ {
		if sigs[i].key() != sigs[0].key() {
			allIdentical = false
			break
		}
	}

	if allIdentical {
		// STATIC MODE: All probes returned the same response.
		// A single O(1) map entry is sufficient.
		b.isDynamic = false
		b.exactSet[sigs[0].key()] = struct{}{}
		return b
	}

	// DYNAMIC MODE: Probes returned varying responses.
	// Group by status code and compute tolerant ranges.
	b.isDynamic = true

	// Still populate the exact set for any responses that appeared multiple times.
	freqMap := make(map[signatureKey]int)
	for _, sig := range sigs {
		k := sig.key()
		freqMap[k]++
		// Add frequently-seen exact signatures (appeared more than once).
		if freqMap[k] >= 2 {
			b.exactSet[k] = struct{}{}
		}
	}

	// Build tolerant ranges grouped by status code.
	statusGroups := make(map[int][]ResponseSignature)
	for _, sig := range sigs {
		statusGroups[sig.StatusCode] = append(statusGroups[sig.StatusCode], sig)
	}

	for statusCode, group := range statusGroups {
		if len(group) < 2 {
			// Not enough data points for tolerance; use exact match only.
			b.exactSet[group[0].key()] = struct{}{}
			continue
		}

		tr := tolerantRange{
			StatusCode: statusCode,
			MinSize:    group[0].Size,
			MaxSize:    group[0].Size,
			MinWords:   group[0].WordCount,
			MaxWords:   group[0].WordCount,
			MinLines:   group[0].LineCount,
			MaxLines:   group[0].LineCount,
		}

		for _, g := range group[1:] {
			if g.Size < tr.MinSize {
				tr.MinSize = g.Size
			}
			if g.Size > tr.MaxSize {
				tr.MaxSize = g.Size
			}
			if g.WordCount < tr.MinWords {
				tr.MinWords = g.WordCount
			}
			if g.WordCount > tr.MaxWords {
				tr.MaxWords = g.WordCount
			}
			if g.LineCount < tr.MinLines {
				tr.MinLines = g.LineCount
			}
			if g.LineCount > tr.MaxLines {
				tr.MaxLines = g.LineCount
			}
		}

		// Add 5% padding to each bound to account for minor runtime variance
		// (e.g., a timestamp that's one digit longer near midnight).
		pad := func(min, max int) (int, int) {
			spread := max - min
			if spread == 0 {
				// Pad by at least 2% of the value itself for zero-spread ranges.
				margin := max / 50
				if margin < 1 {
					margin = 1
				}
				return min - margin, max + margin
			}
			margin := spread / 20 // 5% of spread
			if margin < 1 {
				margin = 1
			}
			return min - margin, max + margin
		}

		tr.MinSize, tr.MaxSize = pad(tr.MinSize, tr.MaxSize)
		tr.MinWords, tr.MaxWords = pad(tr.MinWords, tr.MaxWords)
		tr.MinLines, tr.MaxLines = pad(tr.MinLines, tr.MaxLines)

		b.tolerantRanges = append(b.tolerantRanges, tr)
	}

	return b
}

// ────────────────────────────────────────────────────────────────────────────
// Matching — PHASE 3: O(1) Filtering Engine
// ────────────────────────────────────────────────────────────────────────────

// MatchesSignature checks if a response matches the calibrated baseline.
// For static baselines this is a single O(1) map lookup.
// For dynamic baselines it falls through to a bounded range check.
//
// Returns true if the response IS noise (should be dropped/filtered).
func MatchesSignature(statusCode, size, wordCount, lineCount int, signatures []ResponseSignature) bool {
	// Legacy O(n) path for callers that only have signatures.
	for _, sig := range signatures {
		if statusCode != sig.StatusCode {
			continue
		}
		if sig.Size == 0 {
			continue
		}
		sizeDiff := float64(abs(size-sig.Size)) / float64(sig.Size)
		if sizeDiff < 0.05 {
			return true
		}
		if sig.WordCount > 0 && sig.LineCount > 0 {
			wcDiff := float64(abs(wordCount-sig.WordCount)) / float64(sig.WordCount)
			lcDiff := float64(abs(lineCount-sig.LineCount)) / float64(sig.LineCount)
			if wcDiff < 0.10 && lcDiff < 0.10 {
				return true
			}
		}
	}
	return false
}

// MatchesBaseline is the advanced O(1) filter check.
// Use this instead of MatchesSignature when a Baseline is available.
//
// Returns true if the response IS noise (should be dropped).
func MatchesBaseline(statusCode, size, wordCount, lineCount int, b *Baseline) bool {
	if b == nil {
		return false
	}

	// O(1) exact lookup — covers both static and frequent-dynamic signatures.
	k := makeKey(statusCode, size, wordCount, lineCount)
	if _, ok := b.exactSet[k]; ok {
		return true
	}

	// If baseline is static-only, exact miss means it's a real finding.
	if !b.isDynamic {
		return false
	}

	// Tolerant range check for dynamic pages.
	for _, tr := range b.tolerantRanges {
		if statusCode != tr.StatusCode {
			continue
		}
		if size >= tr.MinSize && size <= tr.MaxSize &&
			wordCount >= tr.MinWords && wordCount <= tr.MaxWords &&
			lineCount >= tr.MinLines && lineCount <= tr.MaxLines {
			return true
		}
	}

	return false
}

// MatchesBaselineBody extends MatchesBaseline with a body-similarity check.
// After the size/word/line strategies miss, it compares the response body
// SimHash against the calibration probes of the same status code. This catches
// soft-404 pages that echo the requested path (so their size varies per
// request) but whose surrounding template is otherwise identical.
//
// Returns true if the response IS noise (should be dropped).
func MatchesBaselineBody(statusCode, size, wordCount, lineCount int, simHash uint64, b *Baseline) bool {
	if MatchesBaseline(statusCode, size, wordCount, lineCount, b) {
		return true
	}
	if b == nil || simHash == 0 {
		return false
	}
	for _, p := range b.probes {
		if p.StatusCode != statusCode || p.SimHash == 0 {
			continue
		}
		if HammingDistance(simHash, p.SimHash) <= simHashThreshold {
			return true
		}
	}
	return false
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP Fetcher (internal)
// ────────────────────────────────────────────────────────────────────────────

// calibrationURL builds a probe URL. When the target carries a FUZZ keyword the
// random probe token is substituted at that position (matching how the scan
// itself resolves URLs); otherwise it is appended as a path segment.
func calibrationURL(targetURL, token string) string {
	token = strings.TrimPrefix(token, "/")
	if strings.Contains(targetURL, "FUZZ") {
		return strings.ReplaceAll(targetURL, "FUZZ", token)
	}
	return strings.TrimSuffix(targetURL, "/") + "/" + token
}

func fetchSignature(ctx context.Context, url string, fetch Fetcher, headers map[string]string) *ResponseSignature {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// The fetch pipeline already reads a size-bounded body for us, so a target
	// that serves a huge SPA shell for every unknown path cannot exhaust memory
	// during calibration.
	resp, body, err := fetch(ctx, req)
	if err != nil || resp == nil {
		return nil
	}

	bodyStr := string(body)
	return &ResponseSignature{
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(bodyStr)),
		LineCount:  strings.Count(bodyStr, "\n") + 1,
		SimHash:    SimHash(bodyStr),
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Utility
// ────────────────────────────────────────────────────────────────────────────

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
