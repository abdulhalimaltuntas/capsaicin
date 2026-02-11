package scanner

import (
	"sync/atomic"
	"time"
)

type Stats struct {
	Total     int64
	Processed int64
	Found     int64
	Errors    int64
	Secrets   int64
	WAFHits   int64
	StartTime time.Time
}

func NewStats(initialTotal int64) *Stats {
	return &Stats{
		Total:     initialTotal,
		StartTime: time.Now(),
	}
}

func (s *Stats) IncrementProcessed() {
	atomic.AddInt64(&s.Processed, 1)
}

func (s *Stats) IncrementFound() {
	atomic.AddInt64(&s.Found, 1)
}

func (s *Stats) IncrementErrors() {
	atomic.AddInt64(&s.Errors, 1)
}

func (s *Stats) IncrementSecrets() {
	atomic.AddInt64(&s.Secrets, 1)
}

func (s *Stats) IncrementWAFHits() {
	atomic.AddInt64(&s.WAFHits, 1)
}

func (s *Stats) IncrementTotal(delta int64) {
	atomic.AddInt64(&s.Total, delta)
}

func (s *Stats) GetProcessed() int64 {
	return atomic.LoadInt64(&s.Processed)
}

func (s *Stats) GetFound() int64 {
	return atomic.LoadInt64(&s.Found)
}

func (s *Stats) GetErrors() int64 {
	return atomic.LoadInt64(&s.Errors)
}

func (s *Stats) GetSecrets() int64 {
	return atomic.LoadInt64(&s.Secrets)
}

func (s *Stats) GetWAFHits() int64 {
	return atomic.LoadInt64(&s.WAFHits)
}

func (s *Stats) GetTotal() int64 {
	return atomic.LoadInt64(&s.Total)
}