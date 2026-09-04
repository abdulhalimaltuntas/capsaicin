package scanner

import "sync"

// taskQueue is an unbounded, thread-safe FIFO queue for scan tasks.
//
// It replaces the previous bounded-channel design where workers fed a
// recursion channel while a recursion goroutine fed the worker channel.
// Because both channels were bounded (Threads*2) and each side could block
// waiting on the other, a recursive scan with enough discovered directories
// could reach a circular wait and deadlock permanently (there is no global
// scan deadline — only SIGINT could break it).
//
// An unbounded queue removes the cycle: producers (initial feed + recursive
// expansion) never block on push, and workers only block when the queue is
// empty and not yet closed.
type taskQueue struct {
	mu      sync.Mutex
	cond    *sync.Cond // signalled on push (wakes waiting pop)
	drained *sync.Cond // signalled on pop  (wakes waiting pushWait)
	items   []Task
	closed  bool
	softCap int
}

func newTaskQueue() *taskQueue {
	q := &taskQueue{}
	q.cond = sync.NewCond(&q.mu)
	q.drained = sync.NewCond(&q.mu)
	return q
}

// push appends a task. It never blocks. Pushing to a closed queue is a no-op.
//
// Workers use this (including recursion/extraction fan-out): a worker that
// blocked on push while holding a task could deadlock the whole pool, so push
// must always return immediately regardless of backlog.
func (q *taskQueue) push(t Task) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.items = append(q.items, t)
	q.mu.Unlock()
	q.cond.Signal()
}

// pushWait appends a task but blocks while the backlog exceeds softCap, applying
// backpressure so an enormous wordlist is not fully materialized in memory at
// once. It is ONLY safe to call from the initial feed goroutine, which never
// holds a task and is therefore not part of the worker drain cycle. Returns
// false if the queue closed while waiting.
func (q *taskQueue) pushWait(t Task) bool {
	q.mu.Lock()
	for q.softCap > 0 && len(q.items) >= q.softCap && !q.closed {
		q.drained.Wait()
	}
	if q.closed {
		q.mu.Unlock()
		return false
	}
	q.items = append(q.items, t)
	q.mu.Unlock()
	q.cond.Signal()
	return true
}

// pop returns the next task, blocking while the queue is empty. It returns
// ok=false once the queue is closed and drained, signalling workers to exit.
func (q *taskQueue) pop() (Task, bool) {
	q.mu.Lock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		q.mu.Unlock()
		return Task{}, false
	}
	t := q.items[0]
	q.items[0] = Task{}
	q.items = q.items[1:]
	q.mu.Unlock()
	q.drained.Signal() // wake a producer blocked on backpressure
	return t, true
}

// close marks the queue closed and wakes all blocked workers. Tasks already
// enqueued are still drained by pop() before it starts returning false.
func (q *taskQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
	q.drained.Broadcast() // release any producer blocked on backpressure
}
