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

type ResponseSignature struct {
	StatusCode int
	Size       int
	WordCount  int
	LineCount  int
}

type CalibrationCache struct {
	mu         sync.RWMutex
	signatures map[string][]ResponseSignature
}

func NewCalibrationCache() *CalibrationCache {
	return &CalibrationCache{
		signatures: make(map[string][]ResponseSignature),
	}
}

func (c *CalibrationCache) Get(targetURL string) ([]ResponseSignature, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sigs, ok := c.signatures[targetURL]
	return sigs, ok
}

func (c *CalibrationCache) Set(targetURL string, sigs []ResponseSignature) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.signatures[targetURL] = sigs
}

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

func PerformCalibration(ctx context.Context, targetURL string, client *http.Client, headers map[string]string, cache *CalibrationCache) []ResponseSignature {
	if sigs, ok := cache.Get(targetURL); ok {
		return sigs
	}

	signatures := make([]ResponseSignature, 0, 3)
	randomPaths := []string{
		fmt.Sprintf("/capsaicin_cal_%d", calRandIntn(999999)),
		fmt.Sprintf("/nonexistent_%d", calRandIntn(999999)),
		fmt.Sprintf("/test404_%d", calRandIntn(999999)),
	}

	for _, path := range randomPaths {
		select {
		case <-ctx.Done():
			return signatures
		default:
		}
		url := strings.TrimSuffix(targetURL, "/") + path
		sig := fetchSignature(ctx, url, client, headers)
		if sig != nil {
			signatures = append(signatures, *sig)
		}
	}

	cache.Set(targetURL, signatures)
	return signatures
}

func fetchSignature(ctx context.Context, url string, client *http.Client, headers map[string]string) *ResponseSignature {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	return &ResponseSignature{
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(string(body))),
		LineCount:  strings.Count(string(body), "\n") + 1,
	}
}

func MatchesSignature(statusCode, size, wordCount, lineCount int, signatures []ResponseSignature) bool {
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

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
