package scanner

import "sync"

// Deduplicator tracks unique findings and merges duplicates by keeping
// the result with the higher severity. Key = URL + "|" + Method.
type Deduplicator struct {
	mu   sync.Mutex
	seen map[string]*Result
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
		return true
	}

	// Keep the result with higher severity; on tie, keep existing.
	if CompareSeverity(r.Severity, existing.Severity) > 0 {
		d.seen[key] = r
		return true
	}
	return false
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
