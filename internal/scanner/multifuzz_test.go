package scanner

import "testing"

func TestComboCount(t *testing.T) {
	lists := []keywordList{
		{keyword: "W1", words: []string{"a", "b", "c"}},
		{keyword: "W2", words: []string{"x", "y"}},
	}
	if got := comboCount(lists, "clusterbomb"); got != 6 {
		t.Errorf("clusterbomb count = %d, want 6", got)
	}
	if got := comboCount(lists, "pitchfork"); got != 2 {
		t.Errorf("pitchfork count = %d, want 2 (min len)", got)
	}
	if got := comboCount(nil, "clusterbomb"); got != 0 {
		t.Errorf("empty lists = %d, want 0", got)
	}
	empty := []keywordList{{keyword: "W1", words: nil}}
	if comboCount(empty, "clusterbomb") != 0 {
		t.Error("a list with no words yields 0 combos")
	}
}

func TestForEachCombo(t *testing.T) {
	lists := []keywordList{
		{keyword: "W1", words: []string{"a", "b"}},
		{keyword: "W2", words: []string{"x", "y"}},
	}
	var cb []map[string]string
	forEachCombo(lists, "clusterbomb", func(m map[string]string) bool { cb = append(cb, m); return true })
	if len(cb) != 4 {
		t.Fatalf("clusterbomb produced %d combos, want 4", len(cb))
	}

	var pf []map[string]string
	forEachCombo(lists, "pitchfork", func(m map[string]string) bool { pf = append(pf, m); return true })
	if len(pf) != 2 || pf[0]["W1"] != "a" || pf[0]["W2"] != "x" || pf[1]["W1"] != "b" || pf[1]["W2"] != "y" {
		t.Errorf("pitchfork zip wrong: %v", pf)
	}

	// early stop
	n := 0
	forEachCombo(lists, "clusterbomb", func(map[string]string) bool { n++; return n < 2 })
	if n != 2 {
		t.Errorf("early stop failed, ran %d", n)
	}
}

func TestApplySubs(t *testing.T) {
	got := applySubs("https://x/W1/W2", map[string]string{"W1": "api", "W2": "v1"})
	if got != "https://x/api/v1" {
		t.Errorf("applySubs = %q", got)
	}
}
