package scanner

import (
	"context"
	"math/rand"
	"net/http"
	"strings"
	"sync"
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

func getRandomUserAgent(rng *rand.Rand) string {
	return userAgents[rng.Intn(len(userAgents))]
}

func worker(
	ctx context.Context,
	tasks <-chan Task,
	results chan<- Result,
	newTasks chan<- Task,
	cfg config.Config,
	client *transport.Client,
	stats *Stats,
	calCache *detection.CalibrationCache,
	done chan<- struct{},
	taskWg *sync.WaitGroup,
	rng *rand.Rand,
	eventCh chan<- ScanEvent,
) {
	defer func() {
		done <- struct{}{}
	}()

	consecutiveErrors := 0
	maxConsecutiveErrors := 5

	for task := range tasks {
		select {
		case <-ctx.Done():
			taskWg.Done()
			continue
		default:
		}

		url := strings.TrimSuffix(task.TargetURL, "/") + "/" + strings.TrimPrefix(task.Path, "/")

		// Track the current URL for live display.
		stats.SetCurrentURL(url)

		// Emit URL-trying event for live UI.
		if eventCh != nil {
			select {
			case eventCh <- ScanEvent{Type: EventURLTrying, URL: url}:
			default: // non-blocking; UI may be slow
			}
		}

		userAgent := getRandomUserAgent(rng)
		result, bodyContent, resp, err := makeRequest(ctx, url, "GET", userAgent, cfg, client)
		stats.IncrementProcessed()

		if err != nil {
			stats.IncrementErrors()
			consecutiveErrors++

			if consecutiveErrors >= maxConsecutiveErrors {
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
				consecutiveErrors = 0
			}
			taskWg.Done()
			continue
		}

		consecutiveErrors = 0

		signatures, _ := calCache.Get(task.TargetURL)
		if detection.MatchesSignature(result.StatusCode, result.Size, result.WordCount, result.LineCount, signatures) {
			taskWg.Done()
			continue
		}

		if result.StatusCode == 405 && !cfg.SafeMode {
			alternativeMethods := []string{"POST", "PUT", "DELETE", "PATCH"}
			for _, method := range alternativeMethods {
				select {
				case <-ctx.Done():
					goto done405
				default:
				}
				methodResult, methodBody, methodResp, err := makeRequest(ctx, url, method, userAgent, cfg, client)
				if err == nil && (methodResult.StatusCode == 200 || methodResult.StatusCode == 201 || methodResult.StatusCode == 204) {
					methodResult.Method = method
					methodResult.Critical = true

					if secrets := detection.DetectSecrets(methodBody); len(secrets) > 0 {
						methodResult.SecretFound = true
						methodResult.SecretTypes = secrets
						stats.IncrementSecrets()
					}

					if techs := detection.DetectTechNames(methodResp, methodBody); len(techs) > 0 {
						methodResult.Technologies = techs
					}

					stats.IncrementFound()
					AssignSeverityAndConfidence(methodResult)
					results <- *methodResult
					break
				}
			}
		}
	done405:

		if isInteresting(result) {
			stats.IncrementFound()

			if result.StatusCode == 200 && len(bodyContent) > 0 {
				if secrets := detection.DetectSecrets(bodyContent); len(secrets) > 0 {
					result.SecretFound = true
					result.SecretTypes = secrets
					stats.IncrementSecrets()
				}
			}

			// Detect technologies from response headers, cookies, and body.
			if resp != nil {
				if techs := detection.DetectTechNames(resp, bodyContent); len(techs) > 0 {
					result.Technologies = techs
				}
			}

			if !cfg.SafeMode && (result.StatusCode == 403 || result.StatusCode == 401) {
				bypassResult := attemptBypassStrategies(ctx, url, userAgent, cfg, client)
				if bypassResult != nil && bypassResult.Result != nil {
					bypassResult.Result.Critical = true

					if secrets := detection.DetectSecrets(bypassResult.Body); len(secrets) > 0 {
						bypassResult.Result.SecretFound = true
						bypassResult.Result.SecretTypes = secrets
						stats.IncrementSecrets()
					}

					AssignSeverityAndConfidence(bypassResult.Result)
					results <- *bypassResult.Result
				}
			}

			if cfg.MaxDepth > 0 && task.Depth < cfg.MaxDepth && isDirectory(result) {
				dirPath := extractPath(url)
				taskWg.Add(1)
				select {
				case newTasks <- Task{
					TargetURL: task.TargetURL,
					Path:      dirPath,
					Depth:     task.Depth + 1,
				}:
				case <-ctx.Done():
					taskWg.Done()
				}
			}

			AssignSeverityAndConfidence(result)
			results <- *result
		}

		taskWg.Done()
	}
}

func makeRequest(ctx context.Context, url, method, userAgent string, cfg config.Config, client *transport.Client) (*Result, string, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, "", nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	for key, value := range cfg.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, body, err := client.DoContext(ctx, req, cfg.RateLimit)
	if err != nil {
		return nil, "", nil, err
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

	return result, bodyContent, resp, nil
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
