package detection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// verifyClient is a dedicated short-timeout client for opt-in secret validation.
// It follows no scan evasion — these are direct read-only calls to the secret's
// own provider to confirm whether the leaked credential is live.
var verifyClient = &http.Client{Timeout: 6 * time.Second}

// VerifySecret attempts a read-only liveness check of a detected secret against
// its provider. Returns "verified" (credential works), "invalid" (rejected), or
// "" (provider not supported / inconclusive). Only ever called under
// --verify-secrets. It never mutates anything on the provider side.
func VerifySecret(ctx context.Context, name, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	switch {
	case strings.Contains(name, "GitHub"):
		return verifyGitHub(ctx, value)
	case strings.Contains(name, "Slack") && strings.HasPrefix(value, "xox"):
		return verifySlack(ctx, value)
	default:
		return "" // provider unsupported for automated verification
	}
}

func verifyGitHub(ctx context.Context, token string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("User-Agent", "capsaicin-verify")
	resp, err := verifyClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		return "verified"
	case 401:
		return "invalid"
	default:
		return ""
	}
}

func verifySlack(ctx context.Context, token string) string {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://slack.com/api/auth.test",
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := verifyClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var out struct {
		OK bool `json:"ok"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return ""
	}
	if out.OK {
		return "verified"
	}
	return "invalid"
}
