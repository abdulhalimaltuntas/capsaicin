package transport

import (
	"math"
	"math/rand"
	"time"
)

// JitterEngine produces stochastic delays using a mix of Gaussian distribution
// (for natural variance between requests) and Pareto distribution (for rare,
// long "reading" pauses).
type JitterEngine struct {
	baseMs    float64
	stddevMs  float64
	paretoMin float64
	paretoAlpha float64
	rng       *rand.Rand
}

// NewJitterEngine initializes a profile.
func NewJitterEngine(profile string, rng *rand.Rand) *JitterEngine {
	j := &JitterEngine{rng: rng}

	switch profile {
	case "aggressive":
		j.baseMs = 5
		j.stddevMs = 2
		j.paretoMin = 0   // Disabled
		j.paretoAlpha = 0
	case "moderate":
		j.baseMs = 50
		j.stddevMs = 15
		j.paretoMin = 200 // Rare 200ms+ pause
		j.paretoAlpha = 2.5
	case "stealth":
		j.baseMs = 300
		j.stddevMs = 100
		j.paretoMin = 1500 // Occasional 1.5s+ pause
		j.paretoAlpha = 2.0
	case "paranoid":
		j.baseMs = 1500
		j.stddevMs = 500
		j.paretoMin = 5000 // Heavy 5s+ reading pauses
		j.paretoAlpha = 1.5
	default:
		// Default to aggressive if unknown or empty.
		j.baseMs = 10
		j.stddevMs = 5
	}
	return j
}

// NextDelay calculates the duration to sleep before the next request.
func (j *JitterEngine) NextDelay() time.Duration {
	if j.baseMs <= 0 {
		return 0
	}

	// Base gaussian delay
	delayMs := j.rng.NormFloat64()*j.stddevMs + j.baseMs
	if delayMs < 0 {
		delayMs = j.baseMs / 2 // Fallback if negative
	}

	// 5% chance of a Pareto "human reading" spike if configured
	if j.paretoMin > 0 && j.rng.Float64() < 0.05 {
		// Inverse transform sampling for Pareto: x_m / (U ^ (1/alpha))
		u := j.rng.Float64()
		spike := j.paretoMin / math.Pow(u, 1.0/j.paretoAlpha)
		
		// Cap the maximum spike to prevent 10-minute sleeps stalling the queue entirely
		if spike > j.paretoMin*15 {
			spike = j.paretoMin * 15
		}
		delayMs += spike
	}

	return time.Duration(delayMs) * time.Millisecond
}
