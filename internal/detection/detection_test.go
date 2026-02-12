package detection

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectSecrets(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected int
	}{
		{
			name:     "AWS key",
			content:  "AKIAIOSFODNN7EXAMPLE",
			expected: 1,
		},
		{
			name:     "JWT token",
			content:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			expected: 1,
		},
		{
			name:     "No secrets",
			content:  "Just some regular text",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := DetectSecrets(tt.content)
			if len(secrets) != tt.expected {
				t.Errorf("expected %d secrets, got %d", tt.expected, len(secrets))
			}
		})
	}
}

func TestDetectWAF(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "Cloudflare",
			headers:  map[string]string{"Server": "cloudflare"},
			expected: "Cloudflare",
		},
		{
			name:     "AWS WAF",
			headers:  map[string]string{"X-Amz-Cf-Id": "test"},
			expected: "AWS WAF",
		},
		{
			name:     "No WAF",
			headers:  map[string]string{"Server": "nginx"},
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

			result := DetectWAF(resp)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
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

	sigs := PerformCalibration(server.URL, client, nil, cache)

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

func TestMatchesSignature(t *testing.T) {
	signatures := []ResponseSignature{
		{StatusCode: 404, Size: 100, WordCount: 10, LineCount: 5},
	}

	tests := []struct {
		name       string
		statusCode int
		size       int
		expected   bool
	}{
		{"exact match", 404, 100, true},
		{"within threshold", 404, 102, true},
		{"different status", 200, 100, false},
		{"size too different", 404, 200, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchesSignature(tt.statusCode, tt.size, signatures)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}