package scanner

import (
	"context"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/abdulhalimaltuntas/capsaicin/internal/detection"
	"github.com/abdulhalimaltuntas/capsaicin/internal/paramfuzz"
	"github.com/abdulhalimaltuntas/capsaicin/internal/probes"
	"github.com/abdulhalimaltuntas/capsaicin/internal/smartfuzz"
)

// markSet is a concurrency-safe "seen once" set used to guarantee each expensive
// side-channel (learn, backup, param-fuzz, active-probe) fires at most once per
// key across all workers.
type markSet struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newMarkSet() *markSet {
	return &markSet{seen: make(map[string]bool)}
}

// once reports whether key was newly added (true) or already present (false).
func (m *markSet) once(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[key] {
		return false
	}
	m.seen[key] = true
	return true
}

// backupSuffixes are appended to a discovered file to probe forgotten backups.
var backupSuffixes = []string{".bak", ".old", ".orig", ".save", ".swp", ".tmp", "~", ".backup", ".1", ".copy"}

// maybeBackups enqueues backup/temp variants of a discovered file so forgotten
// copies (config.php.bak, index.php~) are found. It fires once per file, only for
// paths that carry an extension (real files, not directories).
func (wc *workerContext) maybeBackups(task Task, discoveredURL string) {
	if !wc.cfg.BackupProbe || wc.backupSeen == nil {
		return
	}
	path := strings.TrimPrefix(task.Path, "/")
	if path == "" || strings.HasSuffix(path, "/") {
		return
	}
	dot := strings.LastIndex(path, "/")
	seg := path[dot+1:]
	if !strings.Contains(seg, ".") { // no extension → treat as dir, skip
		return
	}
	if !wc.backupSeen.once(discoveredURL) {
		return
	}
	for _, sfx := range backupSuffixes {
		variant := path + sfx
		wc.taskWg.Add(1)
		wc.queue.push(Task{TargetURL: task.TargetURL, Path: variant, Depth: task.Depth, BaseKey: task.BaseKey})
		wc.stats.IncrementTotal(1)
	}
}

// maybeLearn harvests fresh fuzz candidates from a response body and enqueues the
// new ones as depth-1 tasks against the same target. It fires once per body-source
// URL and is globally deduplicated so a repeated token is only queued once.
func (wc *workerContext) maybeLearn(sourceURL, targetURL, body string) {
	if !wc.cfg.Learn || wc.learnSeen == nil {
		return
	}
	if !wc.learnSeen.once("src:" + sourceURL) {
		return
	}
	for _, w := range smartfuzz.CollectWords(body, 120) {
		if !wc.learnSeen.once("word:" + w) {
			continue
		}
		wc.taskWg.Add(1)
		wc.queue.push(Task{TargetURL: targetURL, Path: w, Depth: 1})
		wc.stats.IncrementTotal(1)
		for _, ext := range wc.cfg.Extensions {
			wc.taskWg.Add(1)
			wc.queue.push(Task{TargetURL: targetURL, Path: w + ext, Depth: 1})
			wc.stats.IncrementTotal(1)
		}
	}
}

// maybeParamFuzz runs hidden-parameter discovery against a URL and emits a
// finding per discovered parameter. It fires once per URL.
func (wc *workerContext) maybeParamFuzz(ctx context.Context, rawURL, userAgent, targetURL string) {
	if !wc.cfg.ParamFuzz || len(wc.paramCandidates) == 0 || wc.paramSeen == nil {
		return
	}
	if !wc.paramSeen.once(rawURL) {
		return
	}

	probe := func(ctx context.Context, u string) (*paramfuzz.Observation, error) {
		status, _, body, err := wc.rawGet(ctx, "GET", u, userAgent, targetURL)
		if err != nil {
			return nil, err
		}
		return &paramfuzz.Observation{
			Status: status,
			Size:   len(body),
			Words:  len(strings.Fields(body)),
			Body:   body,
		}, nil
	}

	miner := paramfuzz.New(probe, wc.paramCandidates)
	found, _ := miner.Mine(ctx, rawURL)
	for _, d := range found {
		result := &Result{
			URL:        rawURL + " [PARAM:" + d.Name + "]",
			StatusCode: 200,
			Method:     "GET",
			Timestamp:  time.Now().Format(time.RFC3339),
			Tags:       []string{"param-discovered", "param:" + d.Name, "param-" + d.Reason},
		}
		result.Severity = SeverityMedium
		result.Confidence = ConfidenceFirm
		wc.stats.IncrementFound()
		select {
		case wc.results <- *result:
		case <-ctx.Done():
			return
		}
	}
}

// maybeActiveProbes runs the active vulnerability checks against a URL and emits a
// finding per confirmed issue. It fires once per URL.
func (wc *workerContext) maybeActiveProbes(ctx context.Context, rawURL, userAgent, targetURL string) {
	if !wc.cfg.ActiveProbes || wc.probeSeen == nil {
		return
	}
	if !wc.probeSeen.once(rawURL) {
		return
	}

	fetch := func(ctx context.Context, method, u string, headers map[string]string) (*probes.Response, error) {
		status, header, body, err := wc.rawGetHeaders(ctx, method, u, userAgent, targetURL, headers)
		if err != nil {
			return nil, err
		}
		return &probes.Response{
			Status:   status,
			Header:   header,
			Body:     body,
			Location: header.Get("Location"),
		}, nil
	}

	prober := probes.New(fetch, wc.cfg.OOBDomain)
	for _, f := range prober.Run(ctx, rawURL) {
		result := &Result{
			URL:        f.URL,
			StatusCode: 200,
			Method:     "GET",
			Timestamp:  time.Now().Format(time.RFC3339),
			Critical:   f.Severity == "critical",
			Tags:       []string{"active-probe", f.Type},
		}
		result.Severity = f.Severity
		result.Confidence = ConfidenceFirm
		if f.Type == "ssrf" {
			result.Confidence = ConfidenceTentative
		}
		wc.stats.IncrementFound()
		select {
		case wc.results <- *result:
		case <-ctx.Done():
			return
		}
	}
}

// probeTakeover fetches the target root and, when its body matches a known
// dangling-service fingerprint, emits a high-severity takeover finding.
func (wc *workerContext) probeTakeover(ctx context.Context, targetURL string, rng *rand.Rand) {
	root := strings.TrimSuffix(targetURL, "/") + "/"
	status, _, body, err := wc.rawGet(ctx, "GET", root, getRandomUserAgent(rng), targetURL)
	if err != nil {
		return
	}
	service := detection.DetectTakeover(body)
	if service == "" {
		return
	}
	result := &Result{
		URL:        root,
		StatusCode: status,
		Size:       len(body),
		Method:     "GET",
		Timestamp:  time.Now().Format(time.RFC3339),
		Critical:   true,
		Tags:       []string{"subdomain-takeover", "takeover:" + service},
	}
	result.Severity = SeverityHigh
	result.Confidence = ConfidenceFirm
	wc.stats.IncrementFound()
	select {
	case wc.results <- *result:
	case <-ctx.Done():
	}
}

// rawGet issues a bare request through the transport (no fingerprint tagging) and
// returns the status, headers and body. Every sub-request counts toward
// processed-request telemetry. It deliberately returns fields rather than the raw
// *http.Response so the response body is closed here, at the single call site.
func (wc *workerContext) rawGet(ctx context.Context, method, rawURL, userAgent, targetURL string) (int, http.Header, string, error) {
	return wc.rawGetHeaders(ctx, method, rawURL, userAgent, targetURL, nil)
}

// rawGetHeaders is rawGet with caller-supplied extra headers (used by probes that
// need to inject markers).
func (wc *workerContext) rawGetHeaders(ctx context.Context, method, rawURL, userAgent, targetURL string, extra map[string]string) (int, http.Header, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range wc.cfg.CustomHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, body, err := wc.client.DoContext(ctx, req, wc.cfg.RateLimit)
	if err != nil {
		return 0, nil, "", err
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	wc.stats.IncrementProcessed()
	return resp.StatusCode, resp.Header, string(body), nil
}
