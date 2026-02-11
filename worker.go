package scanner

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/detection"
	"github.com/capsaicin/scanner/internal/transport"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func worker(
	tasks <-chan Task,
	results chan<- Result,
	newTasks chan<- Task,
	cfg config.Config,
	client *transport.Client,
	stats *Stats,
	calCache *detection.CalibrationCache,
	done chan<- struct{},
) {
	defer func() {
		done <- struct{}{}
	}()

	consecutiveErrors := 0
	maxConsecutiveErrors := 5

	for task := range tasks {
		url := strings.TrimSuffix(task.TargetURL, "/") + "/" + strings.TrimPrefix(task.Path, "/")

		userAgent := getRandomUserAgent()
		result, bodyContent, err := makeRequest(url, "GET", userAgent, cfg, client)
		stats.IncrementProcessed()

		if err != nil {
			stats.IncrementErrors()
			consecutiveErrors++

			if consecutiveErrors >= maxConsecutiveErrors {
				time.Sleep(2 * time.Second)
				consecutiveErrors = 0
			}
			continue
		}

		consecutiveErrors = 0

		signatures, _ := calCache.Get(task.TargetURL)
		if detection.MatchesSignature(result.StatusCode, result.Size, signatures) {
			continue
		}

		if result.StatusCode == 405 {
			alternativeMethods := []string{"POST", "PUT", "DELETE", "PATCH"}
			for _, method := range alternativeMethods {
				methodResult, methodBody, err := makeRequest(url, method, userAgent, cfg, client)
				if err == nil && (methodResult.StatusCode == 200 || methodResult.StatusCode == 201 || methodResult.StatusCode == 204) {
					methodResult.Method = method
					methodResult.Critical = true

					if secrets := detection.DetectSecrets(methodBody); len(secrets) > 0 {
						methodResult.SecretFound = true
						methodResult.SecretTypes = secrets
						stats.IncrementSecrets()
					}

					stats.IncrementFound()
					results <- *methodResult
					break
				}
			}
		}

		if isInteresting(result) {
			stats.IncrementFound()

			if result.StatusCode == 200 && len(bodyContent) > 0 {
				if secrets := detection.DetectSecrets(bodyContent); len(secrets) > 0 {
					result.SecretFound = true
					result.SecretTypes = secrets
					stats.IncrementSecrets()
				}
			}

			if result.StatusCode == 403 || result.StatusCode == 401 {
				bypassResult, bypassBody := attemptBypass(url, userAgent, cfg, client)
				if bypassResult != nil && (bypassResult.StatusCode == 200 || bypassResult.StatusCode == 302) {
					bypassResult.Critical = true

					if secrets := detection.DetectSecrets(bypassBody); len(secrets) > 0 {
						bypassResult.SecretFound = true
						bypassResult.SecretTypes = secrets
						stats.IncrementSecrets()
					}

					results <- *bypassResult
				}
			}

			if cfg.MaxDepth > 0 && task.Depth < cfg.MaxDepth && isDirectory(result) {
				dirPath := extractPath(url)
				newTasks <- Task{
					TargetURL: task.TargetURL,
					Path:      dirPath,
					Depth:     task.Depth + 1,
				}
			}

			results <- *result
		}
	}
}

func makeRequest(url, method, userAgent string, cfg config.Config, client *transport.Client) (*Result, string, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", userAgent)

	for key, value := range cfg.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, body, err := client.Do(req, cfg.RateLimit)
	if err != nil {
		return nil, "", err
	}

	bodyContent := string(body)
	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")

	result := &Result{
		URL:        url,
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(bodyContent)),
		LineCount:  strings.Count(bodyContent, "\n") + 1,
		Method:     method,
		Timestamp:  time.Now().Format(time.RFC3339),
		Server:     server,
		PoweredBy:  poweredBy,
		UserAgent:  userAgent,
	}

	if wafName := detection.DetectWAF(resp); wafName != "" {
		result.WAFDetected = wafName
	}

	return result, bodyContent, nil
}

func attemptBypass(url, userAgent string, cfg config.Config, client *transport.Client) (*Result, string) {
	bypassHeaders := map[string]string{
		"X-Forwarded-For":           "127.0.0.1",
		"X-Original-URL":            extractPath(url),
		"X-Rewrite-URL":             extractPath(url),
		"X-Custom-IP-Authorization": "127.0.0.1",
		"Client-IP":                 "127.0.0.1",
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, ""
	}

	req.Header.Set("User-Agent", userAgent)

	for key, value := range cfg.CustomHeaders {
		req.Header.Set(key, value)
	}

	for key, value := range bypassHeaders {
		req.Header.Set(key, value)
	}

	resp, body, err := client.Do(req, cfg.RateLimit)
	if err != nil {
		return nil, ""
	}

	bodyContent := string(body)
	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")

	result := &Result{
		URL:        url + " [BYPASS]",
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(bodyContent)),
		LineCount:  strings.Count(bodyContent, "\n") + 1,
		Method:     "GET+BYPASS",
		Timestamp:  time.Now().Format(time.RFC3339),
		Server:     server,
		PoweredBy:  poweredBy,
		UserAgent:  userAgent,
	}

	if wafName := detection.DetectWAF(resp); wafName != "" {
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

func init() {
	rand.Seed(time.Now().UnixNano())
}