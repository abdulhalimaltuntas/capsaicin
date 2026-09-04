package detection

import (
	"math/bits"
	"strings"
)

// SimHash computes a 64-bit Charikar SimHash over the token shingles of a
// response body. Near-duplicate bodies (e.g. soft-404 pages that only differ
// by the echoed path) produce hashes with a small Hamming distance, which the
// baseline matcher uses to suppress noise that exact size/word/line matching
// misses.
func SimHash(body string) uint64 {
	if body == "" {
		return 0
	}

	var vector [64]int
	tokens := tokenize(body)
	if len(tokens) == 0 {
		return 0
	}

	for _, tok := range tokens {
		h := fnv64(tok)
		for i := 0; i < 64; i++ {
			if h&(1<<uint(i)) != 0 {
				vector[i]++
			} else {
				vector[i]--
			}
		}
	}

	var fingerprint uint64
	for i := 0; i < 64; i++ {
		if vector[i] > 0 {
			fingerprint |= 1 << uint(i)
		}
	}
	return fingerprint
}

// HammingDistance returns the number of differing bits between two SimHashes.
// A distance <= ~3 indicates near-duplicate content.
func HammingDistance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// simHashThreshold is the maximum Hamming distance at which two bodies are
// treated as the same page for noise filtering.
const simHashThreshold = 4

// tokenize splits a body into lowercase word tokens, capping the amount of
// input scanned so a huge body cannot dominate calibration cost.
func tokenize(body string) []string {
	const maxScan = 256 * 1024
	if len(body) > maxScan {
		body = body[:maxScan]
	}
	fields := strings.FieldsFunc(body, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9')
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) >= 2 {
			out = append(out, strings.ToLower(f))
		}
	}
	return out
}

// fnv64 is the 64-bit FNV-1a hash of a token.
func fnv64(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}
