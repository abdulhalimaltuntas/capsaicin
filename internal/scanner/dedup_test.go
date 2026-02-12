package scanner

import (
	"sync"
	"testing"
)

func TestDedup_UniqueResults(t *testing.T) {
	dedup := NewDeduplicator()

	r1 := &Result{URL: "http://a.com/admin", Method: "GET", Severity: SeverityInfo}
	r2 := &Result{URL: "http://a.com/api", Method: "GET", Severity: SeverityMedium}

	if !dedup.Add(r1) {
		t.Error("expected first result to be added")
	}
	if !dedup.Add(r2) {
		t.Error("expected second result (different URL) to be added")
	}
	if dedup.Len() != 2 {
		t.Errorf("expected 2 unique results, got %d", dedup.Len())
	}
}

func TestDedup_DuplicateKeepsHigherSeverity(t *testing.T) {
	dedup := NewDeduplicator()

	r1 := &Result{URL: "http://a.com/admin", Method: "GET", Severity: SeverityInfo}
	r2 := &Result{URL: "http://a.com/admin", Method: "GET", Severity: SeverityHigh}

	dedup.Add(r1)
	if !dedup.Add(r2) {
		t.Error("expected higher severity duplicate to replace")
	}
	if dedup.Len() != 1 {
		t.Errorf("expected 1 result after dedup, got %d", dedup.Len())
	}

	results := dedup.Results()
	if results[0].Severity != SeverityHigh {
		t.Errorf("expected high severity to be kept, got %q", results[0].Severity)
	}
}

func TestDedup_DuplicateLowerSeverityRejected(t *testing.T) {
	dedup := NewDeduplicator()

	r1 := &Result{URL: "http://a.com/admin", Method: "GET", Severity: SeverityCritical}
	r2 := &Result{URL: "http://a.com/admin", Method: "GET", Severity: SeverityLow}

	dedup.Add(r1)
	if dedup.Add(r2) {
		t.Error("expected lower severity duplicate to be rejected")
	}
	results := dedup.Results()
	if results[0].Severity != SeverityCritical {
		t.Errorf("expected critical severity to be kept, got %q", results[0].Severity)
	}
}

func TestDedup_DifferentMethodsAreSeparate(t *testing.T) {
	dedup := NewDeduplicator()

	r1 := &Result{URL: "http://a.com/api", Method: "GET", Severity: SeverityInfo}
	r2 := &Result{URL: "http://a.com/api", Method: "POST", Severity: SeverityMedium}

	dedup.Add(r1)
	dedup.Add(r2)

	if dedup.Len() != 2 {
		t.Errorf("expected 2 results (different methods), got %d", dedup.Len())
	}
}

func TestDedup_Concurrent(t *testing.T) {
	dedup := NewDeduplicator()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r := &Result{
				URL:      "http://a.com/page",
				Method:   "GET",
				Severity: SeverityInfo,
				Size:     idx,
			}
			dedup.Add(r)
		}(i)
	}
	wg.Wait()

	if dedup.Len() != 1 {
		t.Errorf("concurrent dedup should result in 1 entry, got %d", dedup.Len())
	}
}

func TestDedup_Results(t *testing.T) {
	dedup := NewDeduplicator()
	dedup.Add(&Result{URL: "http://a.com/1", Method: "GET", Severity: SeverityInfo})
	dedup.Add(&Result{URL: "http://a.com/2", Method: "GET", Severity: SeverityHigh})

	results := dedup.Results()
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestDedupKey(t *testing.T) {
	r := &Result{URL: "http://a.com/test", Method: "GET"}
	key := dedupKey(r)
	expected := "http://a.com/test|GET"
	if key != expected {
		t.Errorf("expected key %q, got %q", expected, key)
	}
}
