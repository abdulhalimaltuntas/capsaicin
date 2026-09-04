package scanner

import (
	"bufio"
	"context"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abdulhalimaltuntas/capsaicin/internal/config"
	"github.com/abdulhalimaltuntas/capsaicin/internal/detection"
	"github.com/abdulhalimaltuntas/capsaicin/internal/headless"
	"github.com/abdulhalimaltuntas/capsaicin/internal/logging"
	"github.com/abdulhalimaltuntas/capsaicin/internal/policy"
	"github.com/abdulhalimaltuntas/capsaicin/internal/transport"
)

type Engine struct {
	config     config.Config
	client     *transport.Client
	calCache   *detection.CalibrationCache
	stats      *Stats
	statsReady chan struct{}
}

func NewEngine(cfg config.Config) (*Engine, error) {
	client, err := transport.NewClient(&cfg)
	if err != nil {
		return nil, err
	}

	return &Engine{
		config:     cfg,
		client:     client,
		calCache:   detection.NewCalibrationCache(),
		statsReady: make(chan struct{}),
	}, nil
}

// WaitForStats blocks until the scan engine has initialized its Stats.
// Safe to call from a different goroutine than RunWithEvents.
func (e *Engine) WaitForStats() *Stats {
	<-e.statsReady
	return e.stats
}

// WaitForStatsCtx blocks until the scan engine has initialized its Stats,
// or the context is cancelled. Returns nil if context is cancelled first.
func (e *Engine) WaitForStatsCtx(ctx context.Context) *Stats {
	select {
	case <-e.statsReady:
		return e.stats
	case <-ctx.Done():
		return nil
	}
}

// fetcher returns a detection.Fetcher backed by the full transport pipeline, so
// calibration/recalibration probes are rate-limited, jittered, circuit-broken
// and TLS-spoofed exactly like the main scan requests.
func (e *Engine) fetcher() detection.Fetcher {
	return func(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
		return e.client.DoContext(ctx, req, e.config.RateLimit)
	}
}

// probeVHostBaseline requests a target root with a random Host header to learn
// the default/catch-all vhost response, so real virtual hosts can be told apart.
func (e *Engine) probeVHostBaseline(ctx context.Context, target string) vhBase {
	base := strings.TrimSuffix(target, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, "GET", base, nil)
	if err != nil {
		return vhBase{}
	}
	for k, v := range e.config.CustomHeaders {
		req.Header.Set(k, v)
	}
	req.Host = "capsaicin-baseline-" + randToken() + "." + hostOf(target)
	resp, body, err := e.client.DoContext(ctx, req, e.config.RateLimit)
	if err != nil {
		return vhBase{}
	}
	return vhBase{status: resp.StatusCode, size: len(body)}
}

// vhostName turns a wordlist entry into a Host-header value: a bare word becomes
// word.<target-host>; an entry that already looks like a hostname is used as-is.
func vhostName(word, target string) string {
	if strings.Contains(word, ".") {
		return word
	}
	return word + "." + hostOf(target)
}

func randToken() string {
	return strconv.FormatInt(time.Now().UnixNano()&0xffffff, 36)
}

func (e *Engine) Run(targets []string) ([]Result, *Stats, error) {
	return e.RunContext(context.Background(), targets)
}

func (e *Engine) RunContext(ctx context.Context, targets []string) ([]Result, *Stats, error) {
	return e.RunWithEvents(ctx, targets, nil)
}

func (e *Engine) RunWithEvents(ctx context.Context, targets []string, eventCh chan<- ScanEvent) ([]Result, *Stats, error) {
	if eventCh != nil {
		defer close(eventCh)
	}

	// Word sources. Multi-wordlist (clusterbomb/pitchfork) kicks in only with 2+
	// -w entries and no vhost/inline-word override; the single-wordlist path is
	// otherwise unchanged. `words` also feeds recursion (primary list).
	multi := len(e.config.Wordlists) > 1 && len(e.config.InlineWords) == 0 && !e.config.VHost
	var kwLists []keywordList
	var words []string
	switch {
	case len(e.config.InlineWords) > 0:
		words = e.config.InlineWords
	case multi:
		for _, spec := range e.config.Wordlists {
			w, err := loadWordlist(spec.Path)
			if err != nil {
				return nil, nil, err
			}
			kwLists = append(kwLists, keywordList{keyword: spec.Keyword, words: w})
		}
		if len(kwLists) > 0 {
			words = kwLists[0].words
		}
		for _, kw := range kwLists {
			for _, t := range targets {
				if !strings.Contains(t, kw.keyword) {
					logging.Warn("keyword not present in target URL", "keyword", kw.keyword, "target", t)
				}
			}
		}
	default:
		var err error
		words, err = loadWordlist(e.config.Wordlist)
		if err != nil {
			return nil, nil, err
		}
	}

	matcher, err := NewMatcher(e.config)
	if err != nil {
		return nil, nil, err
	}
	scope := NewScope(e.config.AllowPatterns, e.config.DenyPatterns)

	// Health-check each target and upgrade http→https when only TLS responds.
	targets = e.prepareTargets(ctx, targets)

	// Virtual-host mode fuzzes the Host header, so extensions don't apply and the
	// task count is one per (target, word).
	var initialTaskCount int64
	switch {
	case multi:
		initialTaskCount = int64(len(targets)) * comboCount(kwLists, e.config.FuzzMode)
	case e.config.VHost:
		initialTaskCount = int64(len(targets) * len(words))
	default:
		initialTaskCount = int64(len(targets) * len(words) * (1 + len(e.config.Extensions)))
	}
	stats := NewStats(initialTaskCount)

	// Expose stats to callers waiting on WaitForStats().
	e.stats = stats
	close(e.statsReady)

	// Establish per-target baselines: default-vhost response for vhost mode,
	// otherwise the standard soft-404 calibration.
	vhostBaseline := make(map[string]vhBase)
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return nil, stats, ctx.Err()
		default:
		}
		if e.config.VHost {
			vhostBaseline[target] = e.probeVHostBaseline(ctx, target)
		} else {
			detection.PerformCalibration(ctx, target, e.fetcher(), e.config.CustomHeaders, e.calCache)
		}
	}

	// Rolling recalibration: when auto-calibrate is on, periodically refresh
	// baselines so long scans track drifting error pages.
	if e.config.AutoCalibrate {
		recalCtx, recalStop := context.WithCancel(ctx)
		defer recalStop()
		go e.rollingRecalibrate(recalCtx, targets, stats)
	}

	// dedup is the single source of truth for the finding set: it keeps one
	// entry per URL+Method (highest severity) in first-seen order. Building a
	// separate append-only slice here would double-list a finding whenever a
	// higher-severity duplicate arrived, so the report is read back from dedup.
	dedup := NewDeduplicator()

	// Shared recursion state: guards which directories have already been
	// expanded so two workers don't fan out the same directory twice.
	recur := &recursionState{
		scannedDirs: make(map[string]map[string]bool),
		words:       words,
	}

	queue := newTaskQueue()
	// Backpressure the initial feed so a huge wordlist is not fully materialized
	// as queued tasks up front. Recursion/extraction still push unbounded (they
	// are bounded by discovery), so the worker fan-out never blocks.
	queue.softCap = e.config.Threads * 256
	if queue.softCap < 2048 {
		queue.softCap = 2048
	}
	requested := newRequestedSet()
	audited := newRequestedSet() // per-host security-header audit dedup

	// --resume: skip URLs recorded in a prior run, and append newly-scanned ones.
	if e.config.Resume != "" {
		if n := requested.preload(e.config.Resume); n > 0 {
			logging.Info("resume: skipping already-scanned endpoints", "count", n)
		}
		if f, err := os.OpenFile(e.config.Resume, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			requested.setWriter(bufio.NewWriter(f))
			defer func() {
				requested.flush()
				f.Close()
			}()
		}
	}
	resultChan := make(chan Result, e.config.Threads*2)

	// Optional adaptive subsystems, enabled per-flag.
	var policyEngine *policy.PolicyEngine
	if e.config.AdaptiveRate && !e.config.SafeMode {
		policyEngine = policy.NewPolicyEngine(rand.New(rand.NewSource(time.Now().UnixNano())))
	}

	var extract *extractState
	if e.config.ExtractPaths {
		extract = newExtractState(e.config.ExtractDepth)
	}

	var solver *headless.ChallengeSolver
	var sessions *sessionStore
	if e.config.Headless {
		solver = headless.NewChallengeSolver()
		solver.Timeout = time.Duration(e.config.Timeout) * time.Second
		if e.config.ChromePath != "" {
			solver.ExecPath = e.config.ChromePath
		}
		sessions = newSessionStore()
		defer solver.Close()
	}

	var taskWg sync.WaitGroup
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range resultChan {
			r := result // copy for pointer
			if dedup.Add(&r) {
				// Emit live result event to UI on a newly-surfaced or
				// severity-upgraded finding.
				if eventCh != nil {
					select {
					case eventCh <- ScanEvent{Type: EventResultFound, Result: &r}:
					case <-ctx.Done():
					}
				}
			}

			if result.WAFDetected != "" {
				stats.IncrementWAFHits()
			}
		}
	}()

	wc := &workerContext{
		cfg:           e.config,
		client:        e.client,
		stats:         stats,
		calCache:      e.calCache,
		queue:         queue,
		results:       resultChan,
		taskWg:        &taskWg,
		eventCh:       eventCh,
		matcher:       matcher,
		scope:         scope,
		requested:     requested,
		audited:       audited,
		vhostBaseline: vhostBaseline,
		recur:         recur,
		extract:       extract,
		policy:        policyEngine,
		solver:        solver,
		sessions:      sessions,
	}

	workerDone := make(chan struct{}, e.config.Threads)
	for i := 0; i < e.config.Threads; i++ {
		workerRng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(i)))
		go worker(ctx, wc, workerRng, workerDone)
	}

	taskWg.Add(int(initialTaskCount))

	go func() {
		sentCount := int64(0)
		baseWords := make(map[string]bool, len(words))
		for _, w := range words {
			baseWords[w] = true
		}

		// feed pushes one initial task under backpressure. A false return means
		// the queue closed (cancellation): reconcile the WaitGroup for every
		// not-yet-sent task and stop.
		feed := func(t Task) bool {
			if queue.pushWait(t) {
				sentCount++
				return true
			}
			if remaining := initialTaskCount - sentCount; remaining > 0 {
				taskWg.Add(int(-remaining))
			}
			return false
		}

		cancelled := false
		for _, target := range targets {
			if cancelled {
				break
			}
			// Favicon intel probe (dynamic, independent of initialTaskCount).
			taskWg.Add(1)
			queue.push(Task{TargetURL: target, Kind: taskFavicon})

			// Multi-wordlist (clusterbomb/pitchfork): substitute keywords in the
			// URL for each generated combination.
			if multi {
				forEachCombo(kwLists, e.config.FuzzMode, func(combo map[string]string) bool {
					select {
					case <-ctx.Done():
						if remaining := initialTaskCount - sentCount; remaining > 0 {
							taskWg.Add(int(-remaining))
						}
						cancelled = true
						return false
					default:
					}
					if !feed(Task{TargetURL: target, Subs: combo, Depth: 1}) {
						cancelled = true
						return false
					}
					return true
				})
				continue
			}

			for _, word := range words {
				select {
				case <-ctx.Done():
					remaining := initialTaskCount - sentCount
					if remaining > 0 {
						taskWg.Add(int(-remaining))
					}
					return
				default:
				}

				if e.config.VHost {
					if !feed(Task{TargetURL: target, Kind: taskVHost, Host: vhostName(word, target)}) {
						return
					}
					continue
				}

				if !feed(Task{TargetURL: target, Path: word, Depth: 1}) {
					return
				}
				for _, ext := range e.config.Extensions {
					if !feed(Task{TargetURL: target, Path: word + ext, Depth: 1}) {
						return
					}
				}
			}

			// Target-aware seeding: crawl for extra paths/mutations. These are
			// registered on taskWg dynamically, independent of initialTaskCount.
			if e.config.Spider || e.config.FuzzMode == "dynamic" {
				seedFromSpider(ctx, e.config, queue, stats, &taskWg, target, baseWords, e.fetcher())
			}
		}
	}()

	// Once every enqueued task has been accounted for, close the queue so
	// idle workers wake up and exit. taskWg converges to zero in both the
	// normal-completion and cancellation paths.
	go func() {
		taskWg.Wait()
		queue.close()
	}()

	go func() {
		for i := 0; i < e.config.Threads; i++ {
			<-workerDone
		}
		close(resultChan)
	}()

	wg.Wait()

	// Safe to read without extra synchronization: wg.Wait() has observed the
	// collector goroutine (the only writer to dedup) return.
	return dedup.OrderedResults(), stats, nil
}

// prepareTargets probes each target root and normalizes its scheme:
//   - a plain-http target whose root permanently redirects to https is upgraded,
//     so the scan hits real content instead of a wall of 301s;
//   - a plain-http target that does not respond at all is retried over https.
//
// Unreachable targets are left as-is (the scan will surface the errors) so a
// transient probe failure never silently drops a target.
func (e *Engine) prepareTargets(ctx context.Context, targets []string) []string {
	out := make([]string, len(targets))
	copy(out, targets)

	for i, target := range out {
		select {
		case <-ctx.Done():
			return out
		default:
		}

		status, location, ok := e.probe(ctx, target)
		if ok {
			if strings.HasPrefix(target, "http://") && status >= 300 && status < 400 {
				if u, err := url.Parse(location); err == nil && strings.EqualFold(u.Scheme, "https") {
					out[i] = "https://" + strings.TrimPrefix(target, "http://")
				}
			}
			continue
		}
		if strings.HasPrefix(target, "http://") {
			https := "https://" + strings.TrimPrefix(target, "http://")
			if _, _, ok := e.probe(ctx, https); ok {
				out[i] = https
			}
		}
	}
	return out
}

// probe performs a single best-effort GET against a target root and reports its
// status code and Location header. ok is false when the request errors.
func (e *Engine) probe(ctx context.Context, target string) (status int, location string, ok bool) {
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(e.config.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, "GET", target, nil)
	if err != nil {
		return 0, "", false
	}
	for k, v := range e.config.CustomHeaders {
		req.Header.Set(k, v)
	}
	resp, err := e.client.HTTPClient().Do(req)
	if err != nil {
		return 0, "", false
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location"), true
}

// rollingRecalibrate refreshes target baselines each time processed-request
// count crosses a new multiple of --recal-interval.
func (e *Engine) rollingRecalibrate(ctx context.Context, targets []string, stats *Stats) {
	interval := int64(e.config.RecalInterval)
	if interval < 10 {
		interval = 500
	}
	nextThreshold := interval

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if stats.GetProcessed() < nextThreshold {
				continue
			}
			for _, target := range targets {
				select {
				case <-ctx.Done():
					return
				default:
				}
				detection.Recalibrate(ctx, target, e.fetcher(), e.config.CustomHeaders, e.calCache)
			}
			nextThreshold += interval
		}
	}
}

func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	estimatedLines := 1024
	if info, err := file.Stat(); err == nil && info.Size() > 0 {
		estimatedLines = int(info.Size() / 8)
	}

	words := make([]string, 0, estimatedLines)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	return words, scanner.Err()
}

func CountWordlist(path string) (int, error) {
	words, err := loadWordlist(path)
	if err != nil {
		return 0, err
	}
	return len(words), nil
}
