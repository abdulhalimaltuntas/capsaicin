package wordlist

import "testing"

func TestGet(t *testing.T) {
	common := Get(Common)
	if len(common) < 50 {
		t.Errorf("common list too small: %d entries", len(common))
	}
	params := Get(Params)
	if len(params) < 50 {
		t.Errorf("params list too small: %d entries", len(params))
	}
	if Get("nonexistent") != nil {
		t.Error("unknown list should return nil")
	}
	// Empty name defaults to common.
	if len(Get("")) != len(common) {
		t.Error("empty name should default to common")
	}
}

func TestGetNoCommentsOrDupes(t *testing.T) {
	seen := make(map[string]bool)
	for _, w := range Get(Common) {
		if w == "" {
			t.Error("empty entry leaked through")
		}
		if w[0] == '#' {
			t.Errorf("comment leaked through: %q", w)
		}
		if seen[w] {
			t.Errorf("duplicate entry: %q", w)
		}
		seen[w] = true
	}
}

func TestNames(t *testing.T) {
	names := Names()
	if len(names) != 2 {
		t.Errorf("expected 2 builtin names, got %v", names)
	}
}

func TestSorted(t *testing.T) {
	in := []string{"charlie", "alpha", "bravo"}
	out := Sorted(in)
	if out[0] != "alpha" || out[1] != "bravo" || out[2] != "charlie" {
		t.Errorf("Sorted failed: %v", out)
	}
	// Original must be untouched.
	if in[0] != "charlie" {
		t.Error("Sorted mutated its input")
	}
}
