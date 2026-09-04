package scanner

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/abdulhalimaltuntas/capsaicin/internal/config"
	"github.com/abdulhalimaltuntas/capsaicin/internal/headless"
	"github.com/abdulhalimaltuntas/capsaicin/internal/smartfuzz"
)

// extractState guards on-the-fly link extraction so a path discovered in one
// response is only enqueued once across all workers. It mirrors recursionState
// but keys on the fully-qualified target+path and enforces the --extract-depth
// budget plus a per-response cap to prevent link explosions.
type extractState struct {
	mu         sync.Mutex
	seen       map[string]bool
	maxDepth   int
	maxPerResp int
}

func newExtractState(maxDepth int) *extractState {
	if maxDepth <= 0 {
		maxDepth = 2
	}
	return &extractState{
		seen:       make(map[string]bool),
		maxDepth:   maxDepth,
		maxPerResp: 40,
	}
}

// harvest extracts in-scope links from a response body and enqueues the new
// ones as scan tasks. nextExtDepth is the ExtDepth to stamp on children.
func (e *extractState) harvest(queue *taskQueue, stats *Stats, taskWg *sync.WaitGroup, targetURL, body string, nextExtDepth int) int {
	if nextExtDepth > e.maxDepth {
		return 0
	}
	host := hostOf(targetURL)
	links := smartfuzz.ExtractLinks(body, host)
	if len(links) == 0 {
		return 0
	}

	enqueued := 0
	for _, path := range links {
		if enqueued >= e.maxPerResp {
			break
		}
		key := targetURL + "\x00" + path
		e.mu.Lock()
		if e.seen[key] {
			e.mu.Unlock()
			continue
		}
		e.seen[key] = true
		e.mu.Unlock()

		taskWg.Add(1)
		queue.push(Task{
			TargetURL: targetURL,
			Path:      strings.TrimPrefix(path, "/"),
			Depth:     1,
			ExtDepth:  nextExtDepth,
		})
		stats.IncrementTotal(1)
		enqueued++
	}
	return enqueued
}

// sessionStore caches headless-solved sessions per host so the fast HTTP client
// can reuse challenge cookies without re-driving the browser each request.
type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*headless.SolvedSession
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*headless.SolvedSession)}
}

func (s *sessionStore) get(host string) *headless.SolvedSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[host]
}

func (s *sessionStore) set(host string, sess *headless.SolvedSession) {
	s.mu.Lock()
	s.sessions[host] = sess
	s.mu.Unlock()
}

// seedFromSpider crawls a target and enqueues discovered paths (and, in dynamic
// mode, their mutations) as additional depth-1 tasks. It runs best-effort:
// spider failures are non-fatal and simply yield no extra seeds.
func seedFromSpider(ctx context.Context, cfg config.Config, queue *taskQueue, stats *Stats, taskWg *sync.WaitGroup, target string, baseWords map[string]bool, fetch func(context.Context, *http.Request) (*http.Response, []byte, error)) int {
	spider := smartfuzz.NewSpider(time.Duration(cfg.Timeout) * time.Second)
	if fetch != nil {
		spider.SetFetcher(fetch)
	}
	result, err := spider.Crawl(ctx, target)
	if err != nil || result == nil {
		return 0
	}

	seeds := make([]string, 0, len(result.Paths)+len(result.Words))
	for _, p := range result.Paths {
		seeds = append(seeds, strings.TrimPrefix(p, "/"))
	}
	for _, h := range result.APIHints {
		seeds = append(seeds, strings.TrimPrefix(h, "/"))
	}
	// Words are noisier; only fold them in for dynamic mode.
	if cfg.FuzzMode == "dynamic" {
		seeds = append(seeds, result.Words...)
	}

	if cfg.FuzzMode == "dynamic" {
		mutator := smartfuzz.NewMutator()
		// Bound mutation input to keep fan-out reasonable.
		limit := len(seeds)
		if limit > 100 {
			limit = 100
		}
		seeds = mutator.MutateBatch(seeds[:limit])
	}

	enqueued := 0
	for _, w := range seeds {
		w = strings.TrimSpace(w)
		if w == "" || baseWords[w] {
			continue
		}
		baseWords[w] = true // dedupe within this run

		taskWg.Add(1)
		queue.push(Task{TargetURL: target, Path: w, Depth: 1})
		stats.IncrementTotal(1)
		enqueued++

		for _, ext := range cfg.Extensions {
			taskWg.Add(1)
			queue.push(Task{TargetURL: target, Path: w + ext, Depth: 1})
			stats.IncrementTotal(1)
			enqueued++
		}
	}
	return enqueued
}

// hostOf returns the host[:port] component of a URL, or "" if unparseable.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// looksLikeHTML reports whether a body is worth scraping for links.
func looksLikeHTML(body string) bool {
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	lower := strings.ToLower(head)
	return strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") ||
		strings.Contains(lower, "<a ") || strings.Contains(lower, "<script")
}
