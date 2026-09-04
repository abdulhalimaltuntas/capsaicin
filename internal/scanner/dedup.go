package scanner

import "sync"

// Deduplicator tracks unique findings and merges duplicates by keeping
// the result with the higher severity. Key = URL + "|" + Method.
type Deduplicator struct {
	mu    sync.Mutex
	seen  map[string]*Result
	order []string // dedup keys in first-seen order, for deterministic output
}

// NewDeduplicator creates a thread-safe deduplicator.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]*Result),
	}
}

// dedupKey generates a unique key for a result.
func dedupKey(r *Result) string {
	return r.URL + "|" + r.Method
}

// Add attempts to add a result. Returns true if the result was added or
// replaced an existing one with lower severity. Returns false if a
// higher-severity duplicate already exists.
func (d *Deduplicator) Add(r *Result) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := dedupKey(r)
	existing, ok := d.seen[key]
	if !ok {
		d.seen[key] = r
		d.order = append(d.order, key)
		return true
	}

	// Keep the result with higher severity; on tie, keep existing.
	if CompareSeverity(r.Severity, existing.Severity) > 0 {
		d.seen[key] = r
		return true
	}
	return false
}

// OrderedResults returns the deduplicated findings in first-seen insertion
// order. Each dedup key appears exactly once, carrying its highest-severity
// variant. Unlike Results(), the ordering is deterministic and — crucially —
// a finding replaced by a higher-severity duplicate does not leave its
// superseded copy behind, which makes this the correct set to persist.
func (d *Deduplicator) OrderedResults() []Result {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]Result, 0, len(d.order))
	for _, k := range d.order {
		if r, ok := d.seen[k]; ok {
			out = append(out, *r)
		}
	}
	return out
}

// Results returns deduplicated results as a slice.
func (d *Deduplicator) Results() []Result {
	d.mu.Lock()
	defer d.mu.Unlock()

	results := make([]Result, 0, len(d.seen))
	for _, r := range d.seen {
		results = append(results, *r)
	}
	return results
}

// Len returns the number of unique findings.
func (d *Deduplicator) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
