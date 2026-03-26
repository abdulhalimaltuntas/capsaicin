package headless

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// SolvedSession holds the cookies and headers extracted after solving a JS challenge.
type SolvedSession struct {
	Cookies   []*http.Cookie
	UserAgent string
	SolvedAt  time.Time
}

// ChallengeSolver manages a headless browser pool for solving JS challenges.
// It caches solved sessions per-host to avoid re-solving on every request.
type ChallengeSolver struct {
	mu       sync.RWMutex
	cache    map[string]*SolvedSession // keyed by host
	cacheTTL time.Duration

	// Browser configuration
	Headless    bool
	ExecPath    string // optional custom Chrome/Chromium path
	Timeout     time.Duration
	MaxAttempts int
}

// NewChallengeSolver creates a solver with sane defaults.
func NewChallengeSolver() *ChallengeSolver {
	return &ChallengeSolver{
		cache:       make(map[string]*SolvedSession),
		cacheTTL:    5 * time.Minute, // CF cookies typically last 15-30min
		Headless:    true,
		Timeout:     30 * time.Second,
		MaxAttempts: 3,
	}
}

// GetCachedSession returns a previously solved session if still valid.
func (cs *ChallengeSolver) GetCachedSession(host string) *SolvedSession {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	session, ok := cs.cache[host]
	if !ok {
		return nil
	}
	if time.Since(session.SolvedAt) > cs.cacheTTL {
		return nil // expired
	}
	return session
}

// Solve navigates to the target URL in a headless browser, waits for the JS
// challenge to resolve, and extracts the resulting session cookies + user agent.
// These cookies can then be injected into the fast HTTP/2 transport client.
func (cs *ChallengeSolver) Solve(ctx context.Context, targetURL string) (*SolvedSession, error) {
	var lastErr error

	for attempt := 0; attempt < cs.MaxAttempts; attempt++ {
		session, err := cs.attemptSolve(ctx, targetURL)
		if err != nil {
			lastErr = err
			continue
		}
		return session, nil
	}

	return nil, fmt.Errorf("challenge solve failed after %d attempts: %w", cs.MaxAttempts, lastErr)
}

func (cs *ChallengeSolver) attemptSolve(ctx context.Context, targetURL string) (*SolvedSession, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", cs.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.UserAgent(""), // will be set by page itself
	)

	if cs.ExecPath != "" {
		opts = append(opts, chromedp.ExecPath(cs.ExecPath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(browserCtx, cs.Timeout)
	defer timeoutCancel()

	// Navigate and wait for the challenge to be solved.
	// We detect completion by waiting for the challenge elements to disappear
	// and the page title to change from "Just a moment..." to something else.
	var pageTitle string
	var ua string

	err := chromedp.Run(timeoutCtx,
		chromedp.Navigate(targetURL),

		// Wait for challenge to resolve — title changes when solved.
		chromedp.WaitNotPresent(`#challenge-running`, chromedp.ByID),

		// Additional wait to ensure cookies are fully set.
		chromedp.Sleep(2*time.Second),

		// Extract page title to confirm we passed the challenge.
		chromedp.Title(&pageTitle),

		// Get the browser's actual user agent for header coherence.
		chromedp.EvaluateAsDevTools(`navigator.userAgent`, &ua),
	)
	if err != nil {
		return nil, fmt.Errorf("chromedp navigation failed: %w", err)
	}

	// Verify we actually passed the challenge.
	if pageTitle == "Just a moment..." || pageTitle == "Attention Required" {
		return nil, fmt.Errorf("challenge not solved, page title still: %s", pageTitle)
	}

	// Extract all cookies from the browser context via CDP network domain.
	var cdpCookies []*network.Cookie
	err = chromedp.Run(timeoutCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			cookies, err := network.GetCookies().Do(ctx)
			if err != nil {
				return err
			}
			cdpCookies = cookies
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("cookie extraction failed: %w", err)
	}

	// Convert CDP cookies to standard http.Cookie.
	httpCookies := make([]*http.Cookie, 0, len(cdpCookies))
	for _, c := range cdpCookies {
		httpCookies = append(httpCookies, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		})
	}

	session := &SolvedSession{
		Cookies:   httpCookies,
		UserAgent: ua,
		SolvedAt:  time.Now(),
	}

	// Cache the session for this host.
	cs.mu.Lock()
	// Extract host from URL for caching.
	cs.cache[targetURL] = session
	cs.mu.Unlock()

	return session, nil
}

// InjectCookies applies solved session cookies to an HTTP request.
// This allows the fast HTTP/2 transport to reuse the solved session
// without needing the headless browser for subsequent requests.
func InjectCookies(req *http.Request, session *SolvedSession) {
	for _, cookie := range session.Cookies {
		req.AddCookie(cookie)
	}
	if session.UserAgent != "" {
		req.Header.Set("User-Agent", session.UserAgent)
	}
}

// Close cleans up all cached browser sessions.
func (cs *ChallengeSolver) Close() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.cache = make(map[string]*SolvedSession)
}
