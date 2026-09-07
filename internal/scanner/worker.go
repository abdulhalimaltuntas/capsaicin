package scanner

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
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

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

func getRandomUserAgent(rng *rand.Rand) string {
	return userAgents[rng.Intn(len(userAgents))]
}

// workerContext bundles every dependency a worker needs. Optional adaptive
// subsystems (extract, policy, solver, sessions) are nil when their feature
// flag is off, which keeps the hot path allocation-free for a plain scan.
type workerContext struct {
	cfg      config.Config
	client   *transport.Client
	stats    *Stats
	calCache *detection.CalibrationCache
	queue    *taskQueue
	results  chan<- Result
	taskWg   *sync.WaitGroup
	eventCh  chan<- ScanEvent

	matcher       *Matcher          // ffuf-style match/filter decision; always set
	scope         *Scope            // --allow/--deny host gate; always set (no-op when empty)
	requested     *requestedSet     // request-level dedup; always set
	audited       *requestedSet     // per-host security-header audit dedup; always set
	vhostBaseline map[string]vhBase // default-vhost baseline per target (vhost mode)
	recur         *recursionState
	extract       *extractState             // live link extraction; nil = disabled
	policy        *policy.PolicyEngine      // adaptive bandit; nil = disabled
	solver        *headless.ChallengeSolver // JS challenge solver; nil = disabled
	sessions      *sessionStore             // solved-cookie cache; nil = disabled

	// Optional active-testing side channels. Each dedup set is non-nil only when
	// its feature flag is set, keeping the plain-scan hot path untouched.
	learnSeen       *markSet // --learn dedup (source URLs + harvested words)
	backupSeen      *markSet // --backup-probe dedup (per discovered file)
	paramSeen       *markSet // --param-fuzz dedup (per URL)
	probeSeen       *markSet // --active-probes dedup (per URL)
	paramCandidates []string // candidate params for --param-fuzz
}

// buildURL resolves a task into a request URL. When the target contains the
// FUZZ keyword the payload is substituted at that position (ffuf-style); with no
// keyword the payload is appended as a path segment (classic directory mode).
func buildURL(target, payload string) string {
	if strings.Contains(target, "FUZZ") {
		return strings.ReplaceAll(target, "FUZZ", payload)
	}
	return strings.TrimSuffix(target, "/") + "/" + strings.TrimPrefix(payload, "/")
}

// applySubs substitutes each keyword in the target URL with its word, for
// multi-wordlist (clusterbomb/pitchfork) fuzzing.
func applySubs(target string, subs map[string]string) string {
	out := target
	for kw, w := range subs {
		out = strings.ReplaceAll(out, kw, w)
	}
	return out
}

// recursionState guards directory fan-out so a directory discovered by
// multiple workers is only expanded into wordlist tasks once.
type recursionState struct {
	mu          sync.Mutex
	scannedDirs map[string]map[string]bool
	words       []string
}

// expand enqueues wordlist tasks for a newly discovered directory, unless it
// was already expanded. Each enqueued task is registered on taskWg before the
// caller marks its own task done, so the WaitGroup counter never reaches zero
// prematurely.
func (r *recursionState) expand(queue *taskQueue, cfg config.Config, stats *Stats, taskWg *sync.WaitGroup, targetURL, dirPath string, depth int, baseKey string) {
	r.mu.Lock()
	if r.scannedDirs[targetURL] == nil {
		r.scannedDirs[targetURL] = make(map[string]bool)
	}
	if r.scannedDirs[targetURL][dirPath] {
		r.mu.Unlock()
		return
	}
	r.scannedDirs[targetURL][dirPath] = true
	r.mu.Unlock()

	base := strings.TrimSuffix(dirPath, "/")
	for _, word := range r.words {
		taskWg.Add(1)
		queue.push(Task{TargetURL: targetURL, Path: base + "/" + word, Depth: depth, BaseKey: baseKey})
		stats.IncrementTotal(1)

		for _, ext := range cfg.Extensions {
			taskWg.Add(1)
			queue.push(Task{TargetURL: targetURL, Path: base + "/" + word + ext, Depth: depth, BaseKey: baseKey})
			stats.IncrementTotal(1)
		}
	}
}

// fetcher returns a detection.Fetcher backed by this worker's transport client,
// used for per-directory calibration during recursion.
func (wc *workerContext) fetcher() detection.Fetcher {
	return func(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
		return wc.client.DoContext(ctx, req, wc.cfg.RateLimit)
	}
}

func worker(ctx context.Context, wc *workerContext, rng *rand.Rand, done chan<- struct{}) {
	defer func() {
		done <- struct{}{}
	}()

	consecutiveErrors := 0
	maxConsecutiveErrors := 5

	for {
		task, ok := wc.queue.pop()
		if !ok {
			return
		}

		select {
		case <-ctx.Done():
			wc.taskWg.Done()
			continue
		default:
		}

		// Special task shapes (favicon fingerprint, vhost fuzzing) take their
		// own request path and then account for themselves on taskWg.
		switch task.Kind {
		case taskFavicon:
			wc.probeFavicon(ctx, task.TargetURL, rng)
			wc.taskWg.Done()
			continue
		case taskVHost:
			wc.probeVHost(ctx, task, rng)
			wc.taskWg.Done()
			continue
		case taskTakeover:
			wc.probeTakeover(ctx, task.TargetURL, rng)
			wc.taskWg.Done()
			continue
		}

		var url string
		if len(task.Subs) > 0 {
			url = applySubs(task.TargetURL, task.Subs)
		} else {
			url = buildURL(task.TargetURL, task.Path)
		}

		// Enforce --allow/--deny scope before touching the network.
		if wc.scope.active() && !wc.scope.Allowed(hostOf(url)) {
			wc.taskWg.Done()
			continue
		}

		// Skip endpoints already dispatched (wordlist/extension/spider overlap).
		// Drop the task from the denominator so progress stays accurate.
		if wc.requested != nil && !wc.requested.markNew(wc.cfg.Method+" "+url) {
			wc.stats.IncrementTotal(-1)
			wc.taskWg.Done()
			continue
		}

		// Track the current URL for live display.
		wc.stats.SetCurrentURL(url)

		// Emit URL-trying event for live UI.
		if wc.eventCh != nil {
			select {
			case wc.eventCh <- ScanEvent{Type: EventURLTrying, URL: url}:
			default: // non-blocking; UI may be slow
			}
		}

		// Adaptive pacing: back off proportionally when this host is blocking.
		if wc.policy != nil {
			if d := wc.policy.SuggestedDelay(hostOf(task.TargetURL)); d > 0 {
				select {
				case <-ctx.Done():
				case <-time.After(d):
				}
			}
		}

		userAgent := getRandomUserAgent(rng)
		started := time.Now()
		result, bodyContent, err := wc.makeRequest(ctx, url, wc.cfg.Method, wc.cfg.PostData, userAgent, task.TargetURL)
		wc.stats.IncrementProcessed()

		if err != nil {
			logging.Debug("request failed", "url", url, "method", wc.cfg.Method, "err", err)
			wc.stats.IncrementErrors()
			consecutiveErrors++

			if consecutiveErrors >= maxConsecutiveErrors {
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
				consecutiveErrors = 0
			}
			wc.taskWg.Done()
			continue
		}

		consecutiveErrors = 0

		if wc.policy != nil {
			wc.policy.RecordOutcome(hostOf(task.TargetURL), result.StatusCode,
				float64(time.Since(started).Milliseconds()), result.WAFDetected)
		}

		// If the response is a JS challenge and headless solving is enabled,
		// solve once per host, cache the session, and re-issue the request.
		if wc.solver != nil && headless.NeedsHeadless(bodyContent, result.WAFDetected) {
			if solved := wc.solveChallenge(ctx, task.TargetURL); solved {
				if r2, b2, err2 := wc.makeRequest(ctx, url, wc.cfg.Method, wc.cfg.PostData, userAgent, task.TargetURL); err2 == nil {
					result, bodyContent = r2, b2
				}
			}
		}

		// O(1) baseline filter with body-similarity fallback — primary path.
		// BaseKey selects the per-directory baseline during recursion; empty
		// falls back to the target-root baseline.
		baseKey := task.TargetURL
		if task.BaseKey != "" {
			baseKey = task.BaseKey
		}
		if baseline, ok := wc.calCache.GetBaseline(baseKey); ok {
			simHash := detection.SimHash(bodyContent)
			if detection.MatchesBaselineBody(result.StatusCode, result.Size, result.WordCount, result.LineCount, simHash, baseline) {
				wc.taskWg.Done()
				continue
			}
		} else {
			// Legacy fallback for targets calibrated before restart.
			signatures, _ := wc.calCache.Get(baseKey)
			if detection.MatchesSignature(result.StatusCode, result.Size, result.WordCount, result.LineCount, signatures) {
				wc.taskWg.Done()
				continue
			}
		}

		if result.StatusCode == 405 && !wc.cfg.SafeMode {
			wc.methodFuzz(ctx, url, userAgent, task.TargetURL)
		}

		if wc.matcher.Keep(result.StatusCode, result.Size, result.WordCount, bodyContent) {
			wc.stats.IncrementFound()

			if result.StatusCode == 200 && len(bodyContent) > 0 {
				if matches := detection.DetectSecretsDetailed(bodyContent); len(matches) > 0 {
					names := make([]string, 0, len(matches))
					for _, m := range matches {
						names = append(names, m.Name)
					}
					result.SecretFound = true
					result.SecretTypes = names
					wc.stats.IncrementSecrets()

					// Opt-in live validation: confirm whether leaked credentials
					// actually work (read-only calls to the provider).
					if wc.cfg.VerifySecrets {
						for _, m := range matches {
							if v := detection.VerifySecret(ctx, m.Name, m.Value); v != "" {
								result.Tags = appendUnique(result.Tags, "secret-"+v)
							}
						}
					}
				}
			}

			if !wc.cfg.SafeMode && !wc.cfg.NoBypass && (result.StatusCode == 403 || result.StatusCode == 401) {
				wc.attemptBypass(ctx, url, result.Method, userAgent, task.TargetURL)
			}

			// On-the-fly endpoint discovery from HTML/JS bodies.
			if wc.extract != nil && result.StatusCode == 200 && looksLikeHTML(bodyContent) {
				wc.extract.harvest(wc.queue, wc.stats, wc.taskWg, task.TargetURL, bodyContent, task.ExtDepth+1)
			}

			// Adaptive word learning: mine this body for new fuzz candidates.
			if result.StatusCode == 200 {
				wc.maybeLearn(url, task.TargetURL, bodyContent)
			}

			// Forgotten-backup probing for discovered files.
			if result.StatusCode == 200 || result.StatusCode == 403 {
				wc.maybeBackups(task, url)
			}

			// Active testing on live endpoints: hidden parameters + vuln probes.
			if result.StatusCode == 200 {
				wc.maybeParamFuzz(ctx, url, userAgent, task.TargetURL)
				wc.maybeActiveProbes(ctx, url, userAgent, task.TargetURL)
			}

			if wc.cfg.MaxDepth > 0 && task.Depth < wc.cfg.MaxDepth && isDirectory(result) {
				dirPath := extractPath(url)
				// Per-directory calibration: learn this subdir's own soft-404
				// baseline so recursion isn't drowned by subdir-specific error
				// pages that differ from the site root.
				dirKey := strings.TrimSuffix(task.TargetURL, "/") + dirPath
				if _, done := wc.calCache.GetBaseline(dirKey); !done {
					detection.PerformCalibration(ctx, dirKey, wc.fetcher(), wc.cfg.CustomHeaders, wc.calCache)
				}
				wc.recur.expand(wc.queue, wc.cfg, wc.stats, wc.taskWg, task.TargetURL, dirPath, task.Depth+1, dirKey)
			}

			// Sensitive-content classification (exposed VCS/config/env/backup
			// files, directory listings) enriches the finding's tags/severity.
			for _, t := range detection.ClassifyContent(url, bodyContent) {
				result.Tags = appendUnique(result.Tags, t)
			}

			AssignSeverityAndConfidence(result)
			wc.results <- *result
		}

		wc.taskWg.Done()
	}
}

// vhBase is the default-vhost baseline response for a target root, used to tell
// a real virtual host apart from the catch-all default.
type vhBase struct {
	status int
	size   int
}

// probeFavicon fetches /favicon.ico and emits an informational finding carrying
// the Shodan/Censys mmh3 pivot hash (and a product label when recognized).
func (wc *workerContext) probeFavicon(ctx context.Context, targetURL string, rng *rand.Rand) {
	url := strings.TrimSuffix(targetURL, "/") + "/favicon.ico"
	result, body, err := wc.makeRequest(ctx, url, "GET", "", getRandomUserAgent(rng), targetURL)
	wc.stats.IncrementProcessed()
	if err != nil || result.StatusCode != 200 || len(body) == 0 {
		return
	}

	hash := detection.FaviconHash([]byte(body))
	if hash == 0 {
		return
	}
	result.Tags = appendUnique(result.Tags, fmt.Sprintf("favicon-hash:%d", hash))
	if p := detection.FaviconProduct(hash); p != "" {
		result.Tags = appendUnique(result.Tags, "tech:"+p)
	}
	wc.stats.IncrementFound()
	AssignSeverityAndConfidence(result)
	select {
	case wc.results <- *result:
	case <-ctx.Done():
	}
}

// probeVHost issues a request to the target root with the task's Host header and
// reports it when the response diverges from the default-vhost baseline —
// surfacing internal/hidden virtual hosts served off the same IP.
func (wc *workerContext) probeVHost(ctx context.Context, task Task, rng *rand.Rand) {
	base := strings.TrimSuffix(task.TargetURL, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, "GET", base, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", getRandomUserAgent(rng))
	for k, v := range wc.cfg.CustomHeaders {
		req.Header.Set(k, v)
	}
	req.Host = task.Host // fuzz the Host header

	resp, body, err := wc.client.DoContext(ctx, req, wc.cfg.RateLimit)
	wc.stats.IncrementProcessed()
	if err != nil {
		return
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	b := wc.vhostBaseline[task.TargetURL]
	// Same status and near-identical size as the default host → catch-all, skip.
	if resp.StatusCode == b.status && absInt(len(body)-b.size) <= 48 {
		return
	}

	result := &Result{
		URL:        base + " [VHOST:" + task.Host + "]",
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(string(body))),
		LineCount:  strings.Count(string(body), "\n") + 1,
		Method:     "GET",
		Timestamp:  time.Now().Format(time.RFC3339),
		Server:     resp.Header.Get("Server"),
		Tags:       appendUnique(detection.TechFingerprint(resp), "vhost"),
	}
	wc.stats.IncrementFound()
	AssignSeverityAndConfidence(result)
	select {
	case wc.results <- *result:
	case <-ctx.Done():
	}
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// solveChallenge drives the headless browser once per host and caches the
// resulting session. Returns true if a session is available afterwards.
func (wc *workerContext) solveChallenge(ctx context.Context, targetURL string) bool {
	host := hostOf(targetURL)
	if wc.sessions.get(host) != nil {
		return true
	}
	sess, err := wc.solver.Solve(ctx, targetURL)
	if err != nil || sess == nil {
		return false
	}
	wc.sessions.set(host, sess)
	return true
}

// methodFuzz probes alternative HTTP methods against a 405 endpoint.
func (wc *workerContext) methodFuzz(ctx context.Context, url, userAgent, targetURL string) {
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		select {
		case <-ctx.Done():
			return
		default:
		}
		methodResult, methodBody, err := wc.makeRequest(ctx, url, method, "", userAgent, targetURL)
		if err == nil && (methodResult.StatusCode == 200 || methodResult.StatusCode == 201 || methodResult.StatusCode == 204) {
			methodResult.Method = method
			methodResult.Critical = true

			if secrets := detection.DetectSecrets(methodBody); len(secrets) > 0 {
				methodResult.SecretFound = true
				methodResult.SecretTypes = secrets
				wc.stats.IncrementSecrets()
			}

			wc.stats.IncrementFound()
			AssignSeverityAndConfidence(methodResult)
			wc.results <- *methodResult
			return
		}
	}
}

// attemptBypass tries to defeat a 401/403 gate. When adaptive rate is enabled
// it uses the per-host UCB1 bandit to pick and learn header/method strategies;
// otherwise it falls back to the fixed spoofed-header set.
func (wc *workerContext) attemptBypass(ctx context.Context, url, method, userAgent, targetURL string) {
	// Path-mutation bypass (case, //, /./, ..;/, trailing chars) complements the
	// header-injection strategies and defeats a different class of edge ACL.
	wc.tryPathBypasses(ctx, url, userAgent, targetURL)

	if wc.policy != nil {
		wc.banditBypass(ctx, url, method, userAgent, targetURL)
		return
	}
	if result, body := staticBypass(ctx, url, method, userAgent, wc.cfg, wc.client); result != nil &&
		(result.StatusCode == 200 || result.StatusCode == 302) {
		result.Critical = true
		if secrets := detection.DetectSecrets(body); len(secrets) > 0 {
			result.SecretFound = true
			result.SecretTypes = secrets
			wc.stats.IncrementSecrets()
		}
		AssignSeverityAndConfidence(result)
		wc.results <- *result
	}
}

// banditBypass selects bypass actions via UCB1, rewards each by outcome, and
// emits a result on the first strategy that breaks the gate.
func (wc *workerContext) banditBypass(ctx context.Context, url, method, userAgent, targetURL string) {
	host := hostOf(targetURL)
	bandit := wc.policy.GetBandit(host)

	const maxPulls = 5
	for i := 0; i < maxPulls; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		action := bandit.SelectAction()
		reqMethod := method
		headers := map[string]string{}
		for k, v := range action.Headers {
			headers[k] = v
		}
		if action.Type == policy.ActionMethodFuzz && action.Method != "" {
			reqMethod = action.Method
		}

		result, body := bypassWithHeaders(ctx, url, reqMethod, userAgent, headers, wc.cfg, wc.client)
		if result == nil {
			bandit.Reward(action, policy.RewardFromStatus(0))
			continue
		}
		bandit.Reward(action, policy.RewardFromStatus(result.StatusCode))

		if result.StatusCode == 200 || result.StatusCode == 302 {
			result.URL = url + " [BYPASS:" + action.Name + "]"
			result.Method = reqMethod + "+BYPASS"
			result.Critical = true
			if secrets := detection.DetectSecrets(body); len(secrets) > 0 {
				result.SecretFound = true
				result.SecretTypes = secrets
				wc.stats.IncrementSecrets()
			}
			AssignSeverityAndConfidence(result)
			wc.results <- *result
			return
		}
	}
}

// makeRequest issues a single request through the transport client, injecting
// any headless-solved session cookies for the host, and fingerprints the
// response (WAF + technology tags).
func (wc *workerContext) makeRequest(ctx context.Context, url, method, body, userAgent, targetURL string) (*Result, string, error) {
	var reqBody io.Reader
	hasBody := body != "" && method != "GET" && method != "HEAD"
	if hasBody {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", userAgent)
	for key, value := range wc.cfg.CustomHeaders {
		req.Header.Set(key, value)
	}
	// Default a Content-Type for request bodies unless the user set one via -H.
	if hasBody && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if wc.sessions != nil {
		if sess := wc.sessions.get(hostOf(targetURL)); sess != nil {
			headless.InjectCookies(req, sess)
		}
	}

	resp, respBody, err := wc.client.DoContext(ctx, req, wc.cfg.RateLimit)
	if err != nil {
		return nil, "", err
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	bodyContent := string(respBody)
	result := &Result{
		URL:        url,
		StatusCode: resp.StatusCode,
		Size:       len(respBody),
		WordCount:  len(strings.Fields(bodyContent)),
		LineCount:  strings.Count(bodyContent, "\n") + 1,
		Method:     method,
		Timestamp:  time.Now().Format(time.RFC3339),
		Server:     resp.Header.Get("Server"),
		PoweredBy:  resp.Header.Get("X-Powered-By"),
		UserAgent:  userAgent,
		Tags:       detection.TechFingerprint(resp),
	}

	if wafName := detection.DetectWAF(resp); wafName != "" {
		result.WAFDetected = wafName
	} else if wafName := detection.DetectWAFFromBody(bodyContent, resp.StatusCode); wafName != "" {
		result.WAFDetected = wafName
	}

	// CVE correlation: map fingerprinted server/framework versions to known CVEs.
	for _, cve := range detection.CVEsForServer(result.Server + " " + result.PoweredBy) {
		result.Tags = appendUnique(result.Tags, "cve:"+cve.ID)
	}

	// Security-header audit: cors-wildcard is per-endpoint; posture tags
	// (missing HSTS/XFO/nosniff) are host-level, emitted once per host.
	perEP, hostPosture := detection.SecurityHeaderTags(resp, strings.HasPrefix(url, "https://"))
	result.Tags = append(result.Tags, perEP...)
	if len(hostPosture) > 0 && wc.audited != nil && wc.audited.markNew(hostOf(url)) {
		result.Tags = append(result.Tags, hostPosture...)
	}

	return result, bodyContent, nil
}

// staticBypass is the non-adaptive bypass path: it injects the full fixed set
// of IP-spoofing/rewrite headers in a single request.
func staticBypass(ctx context.Context, url, method, userAgent string, cfg config.Config, client *transport.Client) (*Result, string) {
	headers := map[string]string{
		"X-Forwarded-For":           "127.0.0.1",
		"X-Original-URL":            extractPath(url),
		"X-Rewrite-URL":             extractPath(url),
		"X-Custom-IP-Authorization": "127.0.0.1",
		"Client-IP":                 "127.0.0.1",
		"X-Originating-IP":          "127.0.0.1",
		"X-Remote-IP":               "127.0.0.1",
		"X-Remote-Addr":             "127.0.0.1",
		"X-Host":                    "127.0.0.1",
		"X-Forwarded-Host":          "127.0.0.1",
		"X-Client-IP":               "127.0.0.1",
		"True-Client-IP":            "127.0.0.1",
		"X-Real-IP":                 "127.0.0.1",
		"Forwarded":                 "for=127.0.0.1",
	}
	result, body := bypassWithHeaders(ctx, url, method, userAgent, headers, cfg, client)
	if result != nil {
		result.URL = url + " [BYPASS]"
		result.Method = "GET+BYPASS"
	}
	return result, body
}

// bypassWithHeaders performs one bypass request with the given extra headers.
func bypassWithHeaders(ctx context.Context, url, method, userAgent string, extra map[string]string, cfg config.Config, client *transport.Client) (*Result, string) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, ""
	}

	req.Header.Set("User-Agent", userAgent)
	for key, value := range cfg.CustomHeaders {
		req.Header.Set(key, value)
	}
	for key, value := range extra {
		req.Header.Set(key, value)
	}

	resp, body, err := client.DoContext(ctx, req, cfg.RateLimit)
	if err != nil {
		return nil, ""
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	bodyContent := string(body)
	result := &Result{
		URL:        url,
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(bodyContent)),
		LineCount:  strings.Count(bodyContent, "\n") + 1,
		Method:     method,
		Timestamp:  time.Now().Format(time.RFC3339),
		Server:     resp.Header.Get("Server"),
		PoweredBy:  resp.Header.Get("X-Powered-By"),
		UserAgent:  userAgent,
		Tags:       detection.TechFingerprint(resp),
	}

	if wafName := detection.DetectWAF(resp); wafName != "" {
		result.WAFDetected = wafName
	} else if wafName := detection.DetectWAFFromBody(bodyContent, resp.StatusCode); wafName != "" {
		result.WAFDetected = wafName
	}

	return result, bodyContent
}

func isDirectory(result *Result) bool {
	if result.StatusCode == 301 || result.StatusCode == 302 || result.StatusCode == 403 {
		return true
	}
	if strings.HasSuffix(result.URL, "/") {
		return true
	}
	return false
}

func isInteresting(result *Result) bool {
	if result.StatusCode >= 200 && result.StatusCode < 400 {
		return true
	}
	if result.StatusCode == 401 || result.StatusCode == 403 {
		return true
	}
	return false
}

func extractPath(url string) string {
	parts := strings.SplitN(url, "/", 4)
	if len(parts) >= 4 {
		return "/" + parts[3]
	}
	return "/"
}
