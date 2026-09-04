package scanner

import (
	"bufio"
	"os"
	"sync"
)

// requestedSet tracks which (method, URL) pairs have already been dispatched so
// the same endpoint is not requested twice. Wordlist/extension collisions,
// spider/extract overlap, and recursion can all resolve to a URL that is also a
// plain wordlist entry; without this, those become wasted duplicate requests.
//
// It doubles as the --resume checkpoint: preloaded keys are treated as already
// dispatched (skipped), and newly dispatched keys are appended to the resume log.
type requestedSet struct {
	mu   sync.Mutex
	seen map[string]struct{}
	w    *bufio.Writer // optional resume-log writer
}

func newRequestedSet() *requestedSet {
	return &requestedSet{seen: make(map[string]struct{})}
}

// markNew records key and reports whether it was newly added. A false return
// means the request was already dispatched (or resumed) and should be skipped.
func (r *requestedSet) markNew(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[key]; ok {
		return false
	}
	r.seen[key] = struct{}{}
	if r.w != nil {
		_, _ = r.w.WriteString(key)
		_ = r.w.WriteByte('\n')
	}
	return true
}

// preload marks every key recorded in a resume file as already dispatched.
// Missing/unreadable files are ignored (fresh run). Returns the number loaded.
func (r *requestedSet) preload(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			r.seen[line] = struct{}{}
			n++
		}
	}
	return n
}

// setWriter attaches a resume-log writer that receives each newly dispatched key.
func (r *requestedSet) setWriter(w *bufio.Writer) {
	r.mu.Lock()
	r.w = w
	r.mu.Unlock()
}

// flush persists any buffered resume-log entries.
func (r *requestedSet) flush() {
	r.mu.Lock()
	if r.w != nil {
		r.w.Flush()
	}
	r.mu.Unlock()
}
