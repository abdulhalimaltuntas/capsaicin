package detection

import "regexp"

type SecretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

var Patterns = []SecretPattern{
	{
		Name:    "AWS Access Key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		Name:    "Generic API Key",
		Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)["\s:=]+[a-zA-Z0-9_\-]{20,}`),
	},
	{
		Name:    "Private Key",
		Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	},
	{
		Name:    "JWT Token",
		Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	},
	{
		Name:    "Slack Token",
		Pattern: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}`),
	},
	{
		Name:    "Google API Key",
		Pattern: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	},
}

func DetectSecrets(content string) []string {
	var foundSecrets []string
	secretMap := make(map[string]bool)

	for _, pattern := range Patterns {
		if pattern.Pattern.MatchString(content) {
			if !secretMap[pattern.Name] {
				foundSecrets = append(foundSecrets, pattern.Name)
				secretMap[pattern.Name] = true
			}
		}
	}

	return foundSecrets
}