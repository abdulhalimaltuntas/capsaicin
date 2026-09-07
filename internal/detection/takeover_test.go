package detection

import (
	"strings"
	"testing"
)

func TestDetectTakeover(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"github", "<h1>404</h1> There isn't a GitHub Pages site here.", "GitHub Pages"},
		{"s3", "<Error><Code>NoSuchBucket</Code></Error>", "Amazon S3"},
		{"heroku", "<html>No such app</html>", "Heroku"},
		{"fastly", "Fastly error: unknown domain: foo.example.com", "Fastly"},
		{"clean", "<html><body>Welcome home</body></html>", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectTakeover(tt.body); got != tt.want {
				t.Errorf("DetectTakeover()=%q want %q", got, tt.want)
			}
		})
	}
}

func TestDetectTakeoverTruncation(t *testing.T) {
	// Fingerprint beyond the 8KB scan window is ignored.
	body := strings.Repeat("x", 9000) + "There isn't a GitHub Pages site here"
	if got := DetectTakeover(body); got != "" {
		t.Errorf("expected no match beyond scan window, got %q", got)
	}
}
