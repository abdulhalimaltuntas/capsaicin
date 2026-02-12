package detection

import (
	"math"
	"regexp"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type SecretPattern struct {
	Name           string
	Pattern        *regexp.Regexp
	Severity       Severity
	MinEntropy     float64
	RequireContext bool
}

type SecretMatch struct {
	Name     string
	Severity Severity
	Redacted string
}

var Patterns = []SecretPattern{
	{
		Name:     "AWS Access Key",
		Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "AWS Secret Key",
		Pattern:  regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)["'\s:=]+[A-Za-z0-9/+=]{40}`),
		Severity: SeverityCritical,
	},
	{
		Name:       "Generic API Key",
		Pattern:    regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)["'\s:=]+([a-zA-Z0-9_\-]{20,})`),
		Severity:   SeverityMedium,
		MinEntropy: 3.0,
	},
	{
		Name:     "Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
		Severity: SeverityCritical,
	},
	{
		Name:     "JWT Token",
		Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Slack Token",
		Pattern:  regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Google API Key",
		Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "GitHub Token",
		Pattern:  regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Stripe Secret Key",
		Pattern:  regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Stripe Publishable Key",
		Pattern:  regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
		Severity: SeverityLow,
	},
	{
		Name:     "Heroku API Key",
		Pattern:  regexp.MustCompile(`(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Database Connection String",
		Pattern:  regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^\s"']+:[^\s"']+@[^\s"']+`),
		Severity: SeverityCritical,
	},
	{
		Name:     "Mailgun API Key",
		Pattern:  regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		Severity: SeverityHigh,
	},
	{
		Name:     "Twilio API Key",
		Pattern:  regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Severity: SeverityHigh,
	},
	{
		Name:       "Generic Password",
		Pattern:    regexp.MustCompile(`(?i)(password|passwd|pwd)["'\s:=]+([^\s"']{8,})`),
		Severity:   SeverityMedium,
		MinEntropy: 3.0,
	},
}

func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	var freq [256]int
	total := 0
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
		total++
	}

	entropy := 0.0
	ft := float64(total)
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / ft
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func DetectSecrets(content string) []string {
	matches := DetectSecretsDetailed(content)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.Name)
	}
	return names
}

func DetectSecretsDetailed(content string) []SecretMatch {
	var foundSecrets []SecretMatch
	secretMap := make(map[string]bool)

	for _, pattern := range Patterns {
		match := pattern.Pattern.FindString(content)
		if match == "" {
			continue
		}

		if secretMap[pattern.Name] {
			continue
		}

		if pattern.MinEntropy > 0 {
			valueMatch := extractValue(match)
			if ShannonEntropy(valueMatch) < pattern.MinEntropy {
				continue
			}
		}

		secretMap[pattern.Name] = true
		foundSecrets = append(foundSecrets, SecretMatch{
			Name:     pattern.Name,
			Severity: pattern.Severity,
			Redacted: RedactSecret(match),
		})
	}

	return foundSecrets
}

func extractValue(match string) string {
	for _, sep := range []string{"=", ":", "\"", "'"} {
		if idx := strings.LastIndex(match, sep); idx >= 0 {
			val := strings.TrimSpace(match[idx+1:])
			val = strings.Trim(val, "\"' ")
			if len(val) > 0 {
				return val
			}
		}
	}
	return match
}

func RedactSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}
