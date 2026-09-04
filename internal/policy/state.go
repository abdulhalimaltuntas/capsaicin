package policy

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

// HostProfile stores learned behavioral data for a specific target host.
// It tracks which strategies work best against that host's WAF/backend.
type HostProfile struct {
	Host              string
	PreferredMethod   string  // Best-performing HTTP method
	PreferredJitter   string  // Optimal jitter profile
	AvgResponseTimeMs float64 // Average response latency
	BlockRate         float64 // Percentage of blocked requests (0.0 - 1.0)
	SuccessRate       float64 // Percentage of successful requests
	TotalRequests     int
	WAFType           string  // Detected WAF for this host
	aimdDelayMs       float64 // AIMD-controlled inter-request delay (ms)
}

// PolicyEngine manages per-host bandits and learned profiles.
// It is the central decision-making unit for adaptive scanning.
type PolicyEngine struct {
	mu       sync.RWMutex
	bandits  map[string]*Bandit      // per-host bandit instances
	profiles map[string]*HostProfile // per-host behavioral profiles
	rng      *rand.Rand
}

// NewPolicyEngine creates a new adaptive policy engine.
func NewPolicyEngine(rng *rand.Rand) *PolicyEngine {
	return &PolicyEngine{
		bandits:  make(map[string]*Bandit),
		profiles: make(map[string]*HostProfile),
		rng:      rng,
	}
}

// GetBandit returns the bandit for a specific host, creating one if needed.
func (pe *PolicyEngine) GetBandit(host string) *Bandit {
	pe.mu.RLock()
	b, ok := pe.bandits[host]
	pe.mu.RUnlock()
	if ok {
		return b
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()

	// Double-check after acquiring write lock.
	if b, ok := pe.bandits[host]; ok {
		return b
	}

	b = NewBandit(DefaultBypassActions(), pe.rng)
	pe.bandits[host] = b
	return b
}

// GetProfile returns the behavioral profile for a host.
func (pe *PolicyEngine) GetProfile(host string) *HostProfile {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.profiles[host]
}

// RecordOutcome records the result of a request to update the host's profile.
func (pe *PolicyEngine) RecordOutcome(host string, statusCode int, responseTimeMs float64, wafType string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	profile, ok := pe.profiles[host]
	if !ok {
		profile = &HostProfile{Host: host}
		pe.profiles[host] = profile
	}

	profile.TotalRequests++

	// Update running averages.
	n := float64(profile.TotalRequests)
	profile.AvgResponseTimeMs = profile.AvgResponseTimeMs + (responseTimeMs-profile.AvgResponseTimeMs)/n

	if statusCode == 403 || statusCode == 401 || statusCode == 429 {
		profile.BlockRate = profile.BlockRate + (1.0-profile.BlockRate)/n
		profile.SuccessRate = profile.SuccessRate + (0.0-profile.SuccessRate)/n
	} else if statusCode >= 200 && statusCode < 400 {
		profile.SuccessRate = profile.SuccessRate + (1.0-profile.SuccessRate)/n
		profile.BlockRate = profile.BlockRate + (0.0-profile.BlockRate)/n
	}

	// AIMD congestion control on inter-request delay: multiplicative *increase*
	// of delay when the host pushes back (block/rate-limit/overload), additive
	// *decrease* while it stays healthy — the classic TCP-style controller,
	// applied to pacing. Bounded so a scan can never fully stall.
	const (
		aimdBaseMs = 40.0
		aimdCapMs  = 2000.0
		aimdDecMs  = 12.0
	)
	switch {
	case statusCode == 429 || statusCode == 503 || statusCode == 403:
		profile.aimdDelayMs = math.Min(aimdCapMs, profile.aimdDelayMs*2+aimdBaseMs)
	case statusCode >= 200 && statusCode < 400:
		profile.aimdDelayMs = math.Max(0, profile.aimdDelayMs-aimdDecMs)
	}

	if wafType != "" {
		profile.WAFType = wafType
	}
}

// SuggestedDelay returns a per-request backoff for a host, scaled by how heavily
// it is blocking. Zero means "no throttle needed". It replaces a fixed sleep so
// a lightly-blocking host is barely slowed while a hard-blocking host backs off
// substantially — bounded so a scan can never stall entirely.
func (pe *PolicyEngine) SuggestedDelay(host string) time.Duration {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	profile, ok := pe.profiles[host]
	if !ok || profile.TotalRequests <= 5 {
		return 0
	}
	return time.Duration(profile.aimdDelayMs) * time.Millisecond
}

// ShouldSlowDown returns true if the host is blocking too many requests,
// suggesting the scanner should increase jitter or reduce concurrency.
func (pe *PolicyEngine) ShouldSlowDown(host string) bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	profile, ok := pe.profiles[host]
	if !ok {
		return false
	}

	// If more than 40% of requests are blocked, slow down.
	return profile.BlockRate > 0.4 && profile.TotalRequests > 10
}

// RecommendJitter suggests a jitter profile based on the host's block rate.
func (pe *PolicyEngine) RecommendJitter(host string) string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	profile, ok := pe.profiles[host]
	if !ok {
		return "moderate"
	}

	switch {
	case profile.BlockRate > 0.6:
		return "paranoid"
	case profile.BlockRate > 0.3:
		return "stealth"
	case profile.BlockRate > 0.1:
		return "moderate"
	default:
		return "aggressive"
	}
}
