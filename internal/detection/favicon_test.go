package detection

import "testing"

func TestFaviconHash(t *testing.T) {
	if FaviconHash(nil) != 0 {
		t.Error("empty favicon should hash to 0")
	}
	data := []byte("fake-favicon-bytes-content-here")
	h1 := FaviconHash(data)
	h2 := FaviconHash(data)
	if h1 == 0 || h1 != h2 {
		t.Errorf("favicon hash must be deterministic and non-zero: %d vs %d", h1, h2)
	}
	if FaviconHash([]byte("different")) == h1 {
		t.Error("different content should hash differently")
	}
	if FaviconProduct(116323821) != "GitLab" {
		t.Error("known favicon hash lookup failed")
	}
	if FaviconProduct(999) != "" {
		t.Error("unknown favicon hash should return empty")
	}
}
