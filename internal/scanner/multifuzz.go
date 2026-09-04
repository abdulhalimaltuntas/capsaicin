package scanner

// keywordList pairs a URL keyword (e.g. "W1") with its wordlist entries.
type keywordList struct {
	keyword string
	words   []string
}

// comboCount returns how many substitution combinations a mode produces:
// clusterbomb is the cartesian product; pitchfork zips lists to the shortest.
func comboCount(lists []keywordList, mode string) int64 {
	if len(lists) == 0 {
		return 0
	}
	for _, l := range lists {
		if len(l.words) == 0 {
			return 0
		}
	}
	if mode == "pitchfork" {
		n := len(lists[0].words)
		for _, l := range lists[1:] {
			if len(l.words) < n {
				n = len(l.words)
			}
		}
		return int64(n)
	}
	c := int64(1)
	for _, l := range lists {
		c *= int64(len(l.words))
	}
	return c
}

// forEachCombo invokes fn for each substitution combination, generated lazily so
// a large cartesian product is never fully materialized. fn returns false to
// stop early. A fresh map is passed each call (safe to enqueue).
func forEachCombo(lists []keywordList, mode string, fn func(map[string]string) bool) {
	if len(lists) == 0 {
		return
	}
	for _, l := range lists {
		if len(l.words) == 0 {
			return
		}
	}

	if mode == "pitchfork" {
		n := len(lists[0].words)
		for _, l := range lists[1:] {
			if len(l.words) < n {
				n = len(l.words)
			}
		}
		for i := 0; i < n; i++ {
			combo := make(map[string]string, len(lists))
			for _, l := range lists {
				combo[l.keyword] = l.words[i]
			}
			if !fn(combo) {
				return
			}
		}
		return
	}

	// clusterbomb: odometer over list indices.
	idx := make([]int, len(lists))
	for {
		combo := make(map[string]string, len(lists))
		for i, l := range lists {
			combo[l.keyword] = l.words[idx[i]]
		}
		if !fn(combo) {
			return
		}
		j := len(lists) - 1
		for j >= 0 {
			idx[j]++
			if idx[j] < len(lists[j].words) {
				break
			}
			idx[j] = 0
			j--
		}
		if j < 0 {
			return
		}
	}
}
