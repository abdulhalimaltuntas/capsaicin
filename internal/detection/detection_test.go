package detection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// testSecretFixtures builds fake credential strings at runtime
// so they never appear as complete credential-format strings in source code.
// This prevents CI secret scanners and pattern matchers from flagging test data.
func testSecretFixtures() map[string]string {
	return map[string]string{
		"aws_key":     "AK" + "IA" + "IOSFODNN7" + "TESTONLY1",
		"aws_key_alt": "AK" + "IA" + "IOSFODNN7" + "TESTONLY2",
		"jwt": strings.Join([]string{
			"eyJhbGciOiJ" + "IUzI1NiJ9",
			"eyJzdWIiOiIx" + "MjM0NTY3ODkwIn0",
			"dXKzGiMqQAW" + "lZQsCSJkOoY8Gs_test",
		}, "."),
		"slack":       "xo" + "xb-1234567890" + "123-1234567890123-" + "testonlytestonlytestonlyxx",
		"google_api":  "AI" + "za" + "SyTESTONLY234567890abcdefghijklm_ox",
		"api_key_val": "test_" + "only_" + "key_1234567890abcdefgh",
		"private_key": "-----BEGIN " + "TEST" + " KEY-----",
	}
}

func TestDetectSecrets(t *testing.T) {
	fix := testSecretFixtures()

	tests := []struct {
		name     string
		content  string
		expected int
	}{
		{
			name:     "AWS key",
			content:  fix["aws_key"],
			expected: 1,
		},
		{
			name:     "JWT token",
			content:  fix["jwt"],
			expected: 1,
		},
		{
			name:     "No secrets",
			content:  "Just some regular text",
			expected: 0,
		},
		{
			name:     "empty input",
			content:  "",
			expected: 0,
		},
		{
			name:     "multiple secrets in one body",
			content:  "key=" + fix["aws_key"] + " and also " + fix["jwt"],
			expected: 2,
		},
		{
			name:     "private key header (RSA)",
			content:  "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIE...",
			expected: 1,
		},
		{
			name:     "generic API key with high entropy value",
			content:  `api_key="` + fix["api_key_val"] + `"`,
			expected: 1,
		},
		{
			name:     "slack token",
			content:  fix["slack"],
			expected: 1,
		},
		{
			name:     "Google API key",
			content:  fix["google_api"],
			expected: 1,
		},
		{
			name:     "large body no secrets",
			content:  strings.Repeat("Lorem ipsum dolor sit amet. ", 10000),
			expected: 0,
		},
		{
			name:     "duplicate secret type only counted once",
			content:  fix["aws_key"] + " " + fix["aws_key_alt"],
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := DetectSecrets(tt.content)
			if len(secrets) != tt.expected {
				t.Errorf("expected %d secrets, got %d: %v", tt.expected, len(secrets), secrets)
			}
		})
	}
}

func TestDetectSecrets_ReturnedNames(t *testing.T) {
	fix := testSecretFixtures()
	secrets := DetectSecrets(fix["aws_key"])
	if len(secrets) == 0 {
		t.Fatal("expected at least one secret")
	}
	if secrets[0] != "AWS Access Key" {
		t.Errorf("expected 'AWS Access Key', got %q", secrets[0])
	}
}

func TestDetectSecretsDetailed_Severity(t *testing.T) {
	fix := testSecretFixtures()
	matches := DetectSecretsDetailed(fix["aws_key"])
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	if matches[0].Severity != SeverityCritical {
		t.Errorf("expected critical severity for AWS key, got %q", matches[0].Severity)
	}
	if matches[0].Redacted == fix["aws_key"] {
		t.Error("expected redacted value, got raw secret")
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minValue float64
		maxValue float64
	}{
		{"empty string", "", 0, 0},
		{"single char", "aaaa", 0, 0.01},
		{"low entropy", "abababab", 0.9, 1.1},
		{"high entropy", "aB3$xZ9!kL2@mN5#", 3.5, 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ShannonEntropy(tt.input)
			if e < tt.minValue || e > tt.maxValue {
				t.Errorf("entropy %f not in range [%f, %f]", e, tt.minValue, tt.maxValue)
			}
		})
	}
}

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "*****"},
		{"12345678", "1234****5678"},
	}

	for _, tt := range tests {
		result := RedactSecret(tt.input)
		if len(tt.input) <= 8 {
			if result != strings.Repeat("*", len(tt.input)) {
				t.Errorf("short secret should be fully masked, got %q", result)
			}
		} else {
			if !strings.HasPrefix(result, tt.input[:4]) {
				t.Errorf("expected prefix %q, got %q", tt.input[:4], result)
			}
		}
	}
}

func TestDetectWAF(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		cookies  []*http.Cookie
		expected string
	}{
		{
			name:     "Cloudflare via Server header",
			headers:  map[string]string{"Server": "cloudflare"},
			expected: "Cloudflare",
		},
		{
			name:     "AWS WAF via custom header",
			headers:  map[string]string{"X-Amz-Cf-Id": "test"},
			expected: "AWS WAF",
		},
		{
			name:     "No WAF",
			headers:  map[string]string{"Server": "nginx"},
			expected: "",
		},
		{
			name:     "Cloudflare case insensitive",
			headers:  map[string]string{"Server": "CloudFlare-nginx"},
			expected: "Cloudflare",
		},
		{
			name:     "Akamai",
			headers:  map[string]string{"Server": "AkamaiGHost"},
			expected: "Akamai",
		},
		{
			name:     "Imperva via custom header",
			headers:  map[string]string{"X-Iinfo": "some-value"},
			expected: "Imperva",
		},
		{
			name:     "Sucuri",
			headers:  map[string]string{"Server": "Sucuri/Cloudproxy"},
			expected: "Sucuri",
		},
		{
			name:     "F5 BigIP via cookie",
			cookies:  []*http.Cookie{{Name: "BIGipServer_pool", Value: "abc"}},
			expected: "F5 BigIP",
		},
		{
			name:     "empty headers",
			headers:  map[string]string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c.String())
			}

			result := DetectWAF(resp)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDetectWAFFromBody(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{"cloudflare block page", "<title>Attention Required</title>", "Cloudflare"},
		{"generic WAF block", "Access Denied - your request was blocked", "Generic WAF"},
		{"clean body", "<html><body>Hello</body></html>", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectWAFFromBody(tt.body, 403)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCalibration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	cache := NewCalibrationCache()
	client := &http.Client{}

	sigs := PerformCalibration(context.Background(), server.URL, client, nil, cache)

	if len(sigs) == 0 {
		t.Error("expected calibration signatures")
	}

	cachedSigs, ok := cache.Get(server.URL)
	if !ok {
		t.Error("expected signatures to be cached")
	}

	if len(cachedSigs) != len(sigs) {
		t.Error("cached signatures don't match")
	}
}

func TestCalibration_CacheHit(t *testing.T) {
	cache := NewCalibrationCache()

	preloaded := []ResponseSignature{
		{StatusCode: 404, Size: 100, WordCount: 5, LineCount: 2},
	}
	cache.Set("http://cached.example.com", preloaded)

	sigs := PerformCalibration(context.Background(), "http://cached.example.com", &http.Client{}, nil, cache)

	if len(sigs) != 1 {
		t.Errorf("expected 1 cached signature, got %d", len(sigs))
	}
}

func TestCalibration_WithCustomHeaders(t *testing.T) {
	receivedHeaders := make(map[string]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders["Authorization"] = r.Header.Get("Authorization")
		w.WriteHeader(404)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	cache := NewCalibrationCache()
	headers := map[string]string{"Authorization": "Bearer test123"}

	PerformCalibration(context.Background(), server.URL, &http.Client{}, headers, cache)

	if receivedHeaders["Authorization"] != "Bearer test123" {
		t.Errorf("expected Authorization header, got %q", receivedHeaders["Authorization"])
	}
}

func TestCalibration_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	cache := NewCalibrationCache()
	sigs := PerformCalibration(context.Background(), server.URL, &http.Client{}, nil, cache)

	if len(sigs) == 0 {
		t.Error("expected signatures even for 500 responses")
	}
}

func TestCalibrationCache_Concurrent(t *testing.T) {
	cache := NewCalibrationCache()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "http://example.com"
			if idx%2 == 0 {
				cache.Set(key, []ResponseSignature{{StatusCode: 404, Size: idx}})
			} else {
				cache.Get(key)
			}
		}(i)
	}
	wg.Wait()
}

func TestMatchesSignature(t *testing.T) {
	signatures := []ResponseSignature{
		{StatusCode: 404, Size: 100, WordCount: 10, LineCount: 5},
	}

	tests := []struct {
		name       string
		statusCode int
		size       int
		wordCount  int
		lineCount  int
		expected   bool
	}{
		{"exact match", 404, 100, 10, 5, true},
		{"within size threshold", 404, 102, 8, 3, true},
		{"different status", 200, 100, 10, 5, false},
		{"size and content different", 404, 200, 50, 20, false},
		{"word+line match but size differs", 404, 200, 10, 5, true},
		{"zero size signature skipped", 404, 0, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchesSignature(tt.statusCode, tt.size, tt.wordCount, tt.lineCount, signatures)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMatchesSignature_EmptySignatures(t *testing.T) {
	result := MatchesSignature(404, 100, 0, 0, nil)
	if result {
		t.Error("expected false for nil signatures")
	}

	result = MatchesSignature(404, 100, 0, 0, []ResponseSignature{})
	if result {
		t.Error("expected false for empty signatures")
	}
}

func TestMatchesSignature_ZeroSizeSignature(t *testing.T) {
	signatures := []ResponseSignature{
		{StatusCode: 404, Size: 0},
	}

	result := MatchesSignature(404, 100, 0, 0, signatures)
	if result {
		t.Error("expected false when signature size is 0")
	}
}

func TestAbs(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{5, 5},
		{-5, 5},
		{0, 0},
		{-1, 1},
	}

	for _, tt := range tests {
		result := abs(tt.input)
		if result != tt.expected {
			t.Errorf("abs(%d) = %d, expected %d", tt.input, result, tt.expected)
		}
	}
}

func FuzzDetectSecrets(f *testing.F) {
	f.Add("Just regular text")
	f.Add("")
	f.Add("some random data with numbers 123456 and symbols !@#$%")
	f.Add(strings.Repeat("a", 5000))

	f.Fuzz(func(t *testing.T, content string) {
		secrets := DetectSecrets(content)
		for _, s := range secrets {
			if s == "" {
				t.Error("secret name should not be empty")
			}
		}
	})
}

func FuzzMatchesSignature(f *testing.F) {
	f.Add(404, 100)
	f.Add(200, 0)
	f.Add(500, 999999)
	f.Add(0, 0)

	signatures := []ResponseSignature{
		{StatusCode: 404, Size: 100, WordCount: 10, LineCount: 5},
		{StatusCode: 200, Size: 500, WordCount: 50, LineCount: 20},
	}

	f.Fuzz(func(t *testing.T, statusCode int, size int) {
		MatchesSignature(statusCode, size, 10, 5, signatures)
	})
}
