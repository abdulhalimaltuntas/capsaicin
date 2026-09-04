package transport

import (
	"bufio"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// proxyPool rotates outbound proxies per the configured strategy. It supports
// a single --proxy or a --proxy-file list.
type proxyPool struct {
	proxies  []*url.URL
	strategy string

	rr  uint64     // round-robin cursor
	mu  sync.Mutex // guards rng + failover cursor
	rng *rand.Rand
	cur int // failover: index of the currently-active proxy
}

// newProxyPool builds a pool from --proxy or --proxy-file. Returns (nil, nil)
// when no proxy is configured (caller falls back to environment proxy).
func newProxyPool(single, file, strategy string, rng *rand.Rand) (*proxyPool, error) {
	var raw []string
	switch {
	case file != "":
		lines, err := readLines(file)
		if err != nil {
			return nil, fmt.Errorf("reading proxy file: %w", err)
		}
		raw = lines
	case single != "":
		raw = []string{single}
	default:
		return nil, nil
	}

	pool := &proxyPool{strategy: strategy, rng: rng}
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		if !strings.Contains(p, "://") {
			p = "http://" + p // bare host:port defaults to HTTP proxy
		}
		u, err := url.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy %q: %w", p, err)
		}
		pool.proxies = append(pool.proxies, u)
	}
	if len(pool.proxies) == 0 {
		return nil, nil
	}
	return pool, nil
}

// proxyFunc returns the http.Transport-compatible selector. A nil pool yields
// the standard environment-based proxy behavior.
func (p *proxyPool) proxyFunc() func(*http.Request) (*url.URL, error) {
	if p == nil {
		return http.ProxyFromEnvironment
	}
	return func(*http.Request) (*url.URL, error) { return p.next(), nil }
}

func (p *proxyPool) next() *url.URL {
	switch p.strategy {
	case "random":
		p.mu.Lock()
		u := p.proxies[p.rng.Intn(len(p.proxies))]
		p.mu.Unlock()
		return u
	case "failover":
		p.mu.Lock()
		u := p.proxies[p.cur%len(p.proxies)]
		p.mu.Unlock()
		return u
	default: // round_robin
		i := atomic.AddUint64(&p.rr, 1)
		return p.proxies[int(i)%len(p.proxies)]
	}
}

// markFailed advances the failover cursor so the next request tries a different
// proxy after a transport error. No-op for other strategies.
func (p *proxyPool) markFailed() {
	if p == nil || p.strategy != "failover" {
		return
	}
	p.mu.Lock()
	p.cur++
	p.mu.Unlock()
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}
