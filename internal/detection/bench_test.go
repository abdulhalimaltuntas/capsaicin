package detection

import (
	"strings"
	"testing"
)

func BenchmarkDetectSecrets_NoMatch(b *testing.B) {
	content := strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectSecrets(content)
	}
}

func BenchmarkDetectSecrets_WithMatches(b *testing.B) {
	// Build test credential at runtime to avoid source-level pattern matching
	awsKey := "AK" + "IA" + "IOSFODNN7" + "BENCHONLY1"
	jwtParts := []string{
		"eyJhbGciOiJ" + "IUzI1NiJ9",
		"eyJzdWIiOiIx" + "MjM0NTY3ODkwIn0",
		"dXKzGiMqQAW" + "lZQsCSJkOoY8Gs_bench",
	}
	content := "config: " + awsKey + " and token " + strings.Join(jwtParts, ".")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectSecrets(content)
	}
}

func BenchmarkDetectSecretsDetailed(b *testing.B) {
	awsKey := "AK" + "IA" + "IOSFODNN7" + "BENCHONLY2"
	apiVal := "bench_" + "only_" + "key_1234567890abcdefgh"
	content := "config: " + awsKey + ` and api_key="` + apiVal + `"`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectSecretsDetailed(content)
	}
}

func BenchmarkMatchesSignature(b *testing.B) {
	signatures := []ResponseSignature{
		{StatusCode: 404, Size: 100, WordCount: 10, LineCount: 5},
		{StatusCode: 200, Size: 500, WordCount: 50, LineCount: 20},
		{StatusCode: 403, Size: 200, WordCount: 15, LineCount: 8},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MatchesSignature(404, 101, 10, 5, signatures)
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	s := "aB3xZ9kL2mN5pQ7rS1" // high entropy, no credential format
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShannonEntropy(s)
	}
}

func BenchmarkRedactSecret(b *testing.B) {
	secret := "TEST_ONLY_NOT_REAL_KEY"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RedactSecret(secret)
	}
}
