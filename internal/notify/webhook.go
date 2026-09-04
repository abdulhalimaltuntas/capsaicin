// Package notify delivers scan findings to external endpoints (Slack, Discord,
// or a generic JSON webhook).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/scanner"
)

var webhookClient = &http.Client{Timeout: 10 * time.Second}

// SendWebhook posts a summary of findings at or above minSeverity to the given
// webhook URL. It shapes the payload for Slack ({"text"}), Discord ({"content"})
// or a generic endpoint (both keys). Returns the number of findings reported.
func SendWebhook(ctx context.Context, webhookURL string, results []scanner.Result, minSeverity string) (int, error) {
	var hits []scanner.Result
	for i := range results {
		if scanner.SeverityAtOrAbove(results[i].Severity, minSeverity) {
			hits = append(hits, results[i])
		}
	}
	if len(hits) == 0 {
		return 0, nil
	}

	sort.Slice(hits, func(i, j int) bool {
		return scanner.CompareSeverity(hits[i].Severity, hits[j].Severity) > 0
	})

	text := formatMessage(hits, minSeverity)

	lower := strings.ToLower(webhookURL)
	var payload map[string]string
	switch {
	case strings.Contains(lower, "discord"):
		payload = map[string]string{"content": text}
	case strings.Contains(lower, "slack") || strings.Contains(lower, "hooks.slack"):
		payload = map[string]string{"text": text}
	default:
		payload = map[string]string{"text": text, "content": text}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := webhookClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return len(hits), nil
}

func formatMessage(hits []scanner.Result, minSeverity string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🌶 Capsaicin: %d finding(s) at or above %q severity\n", len(hits), minSeverity)
	const maxList = 15
	for i, r := range hits {
		if i >= maxList {
			fmt.Fprintf(&b, "…and %d more\n", len(hits)-maxList)
			break
		}
		line := fmt.Sprintf("• [%s] %d %s", strings.ToUpper(r.Severity), r.StatusCode, r.URL)
		if r.SecretFound && len(r.SecretTypes) > 0 {
			line += " (secret: " + strings.Join(r.SecretTypes, ", ") + ")"
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}
