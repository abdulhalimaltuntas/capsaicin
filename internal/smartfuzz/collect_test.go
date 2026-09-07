package smartfuzz

import "testing"

func TestCollectWords(t *testing.T) {
	body := `<html><body>
		<a href="/admin/dashboard">Admin</a>
		<a href="/api/invoices">Invoices</a>
		<script src="/static/js/app.js"></script>
		fetch("/internal/webhook")
		<div class="container">Welcome to your account</div>
	</body></html>`

	words := CollectWords(body, 100)
	set := make(map[string]bool)
	for _, w := range words {
		set[w] = true
	}

	// Path segments should be harvested.
	for _, want := range []string{"admin", "dashboard", "invoices", "internal", "webhook"} {
		if !set[want] {
			t.Errorf("expected %q in collected words %v", want, words)
		}
	}
	// Static asset filenames should be filtered.
	if set["app.js"] {
		t.Error("app.js asset should be filtered out")
	}
	// Boring words should be filtered.
	if set["your"] || set["the"] {
		t.Error("boring words should be filtered out")
	}
}

func TestCollectWordsLimit(t *testing.T) {
	body := ""
	for i := 0; i < 500; i++ {
		body += `<a href="/path` + string(rune('a'+i%26)) + `xyz` + itoa(i) + `">x</a>`
	}
	words := CollectWords(body, 20)
	if len(words) > 20 {
		t.Errorf("limit not respected: got %d words", len(words))
	}
}

func TestCollectWordsEmpty(t *testing.T) {
	if got := CollectWords("", 50); len(got) != 0 {
		t.Errorf("empty body should yield no words, got %v", got)
	}
}

// itoa is a tiny helper to avoid importing strconv in the test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
