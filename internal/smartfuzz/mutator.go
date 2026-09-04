package smartfuzz

import (
	"fmt"
	"strings"
)

// Mutator generates intelligent permutations from seed words.
// It applies common naming conventions, versioning patterns, and path
// structures observed in real-world web applications.
type Mutator struct {
	rules []MutationRule
}

// MutationRule defines a single transformation pattern.
type MutationRule struct {
	Name     string
	Generate func(word string) []string
}

// NewMutator creates a mutator with the full set of transformation rules.
func NewMutator() *Mutator {
	return &Mutator{
		rules: defaultRules(),
	}
}

// Mutate applies all mutation rules to a seed word and returns unique permutations.
func (m *Mutator) Mutate(word string) []string {
	seen := make(map[string]bool)
	seen[word] = true
	var results []string

	for _, rule := range m.rules {
		for _, variant := range rule.Generate(word) {
			if !seen[variant] && variant != "" {
				seen[variant] = true
				results = append(results, variant)
			}
		}
	}

	return results
}

// MutateBatch applies mutation rules to multiple seed words.
func (m *Mutator) MutateBatch(words []string) []string {
	seen := make(map[string]bool)
	var results []string

	for _, word := range words {
		if !seen[word] {
			seen[word] = true
			results = append(results, word)
		}
		for _, variant := range m.Mutate(word) {
			if !seen[variant] {
				seen[variant] = true
				results = append(results, variant)
			}
		}
	}

	return results
}

func defaultRules() []MutationRule {
	return []MutationRule{
		{
			Name: "version_suffix",
			Generate: func(word string) []string {
				versions := []string{"v1", "v2", "v3", "v4"}
				var r []string
				for _, v := range versions {
					r = append(r, word+"_"+v)
					r = append(r, word+"-"+v)
					r = append(r, word+"/"+v)
				}
				return r
			},
		},
		{
			Name: "environment_suffix",
			Generate: func(word string) []string {
				envs := []string{"dev", "staging", "test", "prod", "qa", "uat", "sandbox", "beta", "internal", "debug"}
				var r []string
				for _, e := range envs {
					r = append(r, word+"-"+e)
					r = append(r, word+"_"+e)
					r = append(r, word+"/"+e)
				}
				return r
			},
		},
		{
			Name: "common_prefix",
			Generate: func(word string) []string {
				prefixes := []string{"old", "new", "backup", "bak", "tmp", "temp", "test", "dev", "private", "hidden"}
				var r []string
				for _, p := range prefixes {
					r = append(r, p+"-"+word)
					r = append(r, p+"_"+word)
					r = append(r, p+"/"+word)
				}
				return r
			},
		},
		{
			Name: "api_patterns",
			Generate: func(word string) []string {
				return []string{
					"api/" + word,
					"api/v1/" + word,
					"api/v2/" + word,
					"rest/" + word,
					"graphql/" + word,
					"internal/" + word,
					"admin/" + word,
				}
			},
		},
		{
			Name: "backup_extensions",
			Generate: func(word string) []string {
				exts := []string{".bak", ".old", ".backup", ".orig", ".copy", ".tmp", ".swp", "~", ".save"}
				var r []string
				for _, e := range exts {
					r = append(r, word+e)
				}
				return r
			},
		},
		{
			Name: "case_variations",
			Generate: func(word string) []string {
				return []string{
					strings.ToUpper(word),
					strings.Title(word),
					strings.ToLower(word),
				}
			},
		},
		{
			Name: "numeric_suffix",
			Generate: func(word string) []string {
				var r []string
				for i := 0; i <= 9; i++ {
					r = append(r, fmt.Sprintf("%s%d", word, i))
					r = append(r, fmt.Sprintf("%s_%d", word, i))
				}
				return r
			},
		},
		{
			Name: "config_files",
			Generate: func(word string) []string {
				return []string{
					word + "/.env",
					word + "/config.json",
					word + "/config.yml",
					word + "/config.yaml",
					word + "/settings.json",
					word + "/.git/config",
					word + "/package.json",
					word + "/composer.json",
					word + "/web.config",
					word + "/wp-config.php",
				}
			},
		},
		{
			Name: "separator_swap",
			Generate: func(word string) []string {
				var results []string
				if strings.Contains(word, "-") {
					results = append(results, strings.ReplaceAll(word, "-", "_"))
					results = append(results, strings.ReplaceAll(word, "-", "."))
				}
				if strings.Contains(word, "_") {
					results = append(results, strings.ReplaceAll(word, "_", "-"))
					results = append(results, strings.ReplaceAll(word, "_", "."))
				}
				return results
			},
		},
	}
}
