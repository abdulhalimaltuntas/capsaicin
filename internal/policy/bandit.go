package policy

import (
	"math"
	"math/rand"
	"sync"
)

// Action represents a single evasion technique that can be selected.
type Action struct {
	Name    string            // Human-readable identifier
	Type    ActionType        // Category of action
	Headers map[string]string // Headers to inject (for bypass actions)
	Method  string            // HTTP method override (for method-fuzz actions)
	Jitter  string            // Jitter profile override
}

// ActionType categorizes actions for the bandit.
type ActionType int

const (
	ActionBypassHeader ActionType = iota
	ActionMethodFuzz
	ActionJitterTune
)

// armStats tracks the reward statistics for a single arm (action).
type armStats struct {
	pulls      int
	totalReward float64
}

// Bandit implements the Upper Confidence Bound 1 (UCB1) algorithm for
// multi-armed bandit action selection. It balances exploration of untested
// strategies with exploitation of known-good strategies.
type Bandit struct {
	mu      sync.Mutex
	arms    []Action
	stats   []armStats
	total   int
	rng     *rand.Rand
}

// NewBandit initializes a bandit with the given action space.
func NewBandit(actions []Action, rng *rand.Rand) *Bandit {
	return &Bandit{
		arms:  actions,
		stats: make([]armStats, len(actions)),
		rng:   rng,
	}
}

// SelectAction picks the next action using UCB1.
// If any arm hasn't been tried yet, it is selected first (exploration guarantee).
// Otherwise, the arm with the highest UCB1 score is chosen.
func (b *Bandit) SelectAction() Action {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Phase 1: Ensure every arm is tried at least once.
	for i, s := range b.stats {
		if s.pulls == 0 {
			return b.arms[i]
		}
	}

	// Phase 2: UCB1 selection.
	bestIdx := 0
	bestScore := -1.0
	logTotal := math.Log(float64(b.total))

	for i, s := range b.stats {
		avgReward := s.totalReward / float64(s.pulls)
		exploration := math.Sqrt(2.0 * logTotal / float64(s.pulls))
		score := avgReward + exploration

		if score > bestScore {
			bestScore = score
			bestIdx = i
		}
	}

	return b.arms[bestIdx]
}

// Reward records the outcome of using a specific action.
// reward should be between 0.0 (total failure/block) and 1.0 (full success).
func (b *Bandit) Reward(action Action, reward float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, arm := range b.arms {
		if arm.Name == action.Name {
			b.stats[i].pulls++
			b.stats[i].totalReward += reward
			b.total++
			return
		}
	}
}

// Stats returns a snapshot of the current arm statistics for debugging/logging.
func (b *Bandit) Stats() map[string]float64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make(map[string]float64, len(b.arms))
	for i, arm := range b.arms {
		if b.stats[i].pulls > 0 {
			result[arm.Name] = b.stats[i].totalReward / float64(b.stats[i].pulls)
		} else {
			result[arm.Name] = 0
		}
	}
	return result
}

// DefaultBypassActions returns the standard set of bypass header combinations.
func DefaultBypassActions() []Action {
	return []Action{
		{Name: "xff-localhost", Type: ActionBypassHeader, Headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{Name: "xff-10net", Type: ActionBypassHeader, Headers: map[string]string{"X-Forwarded-For": "10.0.0.1"}},
		{Name: "true-client-ip", Type: ActionBypassHeader, Headers: map[string]string{"True-Client-IP": "127.0.0.1"}},
		{Name: "x-real-ip", Type: ActionBypassHeader, Headers: map[string]string{"X-Real-IP": "127.0.0.1"}},
		{Name: "x-original-url", Type: ActionBypassHeader, Headers: map[string]string{"X-Original-URL": "/"}},
		{Name: "x-rewrite-url", Type: ActionBypassHeader, Headers: map[string]string{"X-Rewrite-URL": "/"}},
		{Name: "x-host", Type: ActionBypassHeader, Headers: map[string]string{"X-Host": "localhost"}},
		{Name: "forwarded", Type: ActionBypassHeader, Headers: map[string]string{"Forwarded": "for=127.0.0.1"}},
		{Name: "x-forwarded-host", Type: ActionBypassHeader, Headers: map[string]string{"X-Forwarded-Host": "localhost"}},
		{Name: "x-client-ip", Type: ActionBypassHeader, Headers: map[string]string{"X-Client-IP": "127.0.0.1"}},
		{Name: "combo-xff-xri", Type: ActionBypassHeader, Headers: map[string]string{
			"X-Forwarded-For": "127.0.0.1",
			"X-Real-IP":       "127.0.0.1",
			"True-Client-IP":  "127.0.0.1",
		}},
		{Name: "method-post", Type: ActionMethodFuzz, Method: "POST"},
		{Name: "method-put", Type: ActionMethodFuzz, Method: "PUT"},
		{Name: "method-delete", Type: ActionMethodFuzz, Method: "DELETE"},
		{Name: "method-patch", Type: ActionMethodFuzz, Method: "PATCH"},
		{Name: "method-options", Type: ActionMethodFuzz, Method: "OPTIONS"},
	}
}

// RewardFromStatus maps an HTTP status code to a normalized reward value.
func RewardFromStatus(statusCode int) float64 {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return 1.0
	case statusCode == 302 || statusCode == 301:
		return 0.7
	case statusCode == 403 || statusCode == 401:
		return 0.0
	case statusCode == 429:
		return -0.5 // rate limited — penalize heavily
	case statusCode >= 500:
		return -0.3
	default:
		return 0.1
	}
}
