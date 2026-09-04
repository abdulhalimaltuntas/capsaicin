package transport

import (
	"math/rand"
	"os"
	"testing"
	"time"
)

func TestProxyPool(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	if p, err := newProxyPool("", "", "random", rng); err != nil || p != nil {
		t.Errorf("no proxy config should yield nil pool, got %v %v", p, err)
	}

	p, err := newProxyPool("127.0.0.1:8080", "", "round_robin", rng)
	if err != nil || p == nil {
		t.Fatalf("single proxy: %v %v", p, err)
	}
	if u := p.next(); u == nil || u.Host != "127.0.0.1:8080" {
		t.Errorf("proxy url wrong: %v", u)
	}
	// proxyFunc on a nil pool is safe (falls back to environment behavior).
	if (*proxyPool)(nil).proxyFunc() == nil {
		t.Error("nil pool proxyFunc should be non-nil")
	}
	// A real pool's proxyFunc returns the rotating selector.
	if p.proxyFunc() == nil {
		t.Error("pool proxyFunc should be non-nil")
	}

	// random strategy does not panic and returns a proxy.
	pr, _ := newProxyPool("", "", "random", rng)
	_ = pr // nil (no config)
	rp, _ := newProxyPool("http://127.0.0.1:9", "", "random", rng)
	if rp.next() == nil {
		t.Error("random next should return a proxy")
	}
}

func TestProxyPool_FileAndFailover(t *testing.T) {
	f, _ := os.CreateTemp("", "proxies-*.txt")
	defer os.Remove(f.Name())
	f.WriteString("# comment\nhttp://127.0.0.1:1\nhttp://127.0.0.1:2\n")
	f.Close()

	p, err := newProxyPool("", f.Name(), "failover", rand.New(rand.NewSource(1)))
	if err != nil || p == nil {
		t.Fatalf("file proxy pool: %v %v", p, err)
	}
	if len(p.proxies) != 2 {
		t.Fatalf("expected 2 proxies (comment skipped), got %d", len(p.proxies))
	}
	first := p.next().Host
	p.markFailed()
	if p.next().Host == first {
		t.Error("failover should advance to a different proxy after markFailed")
	}
	// markFailed on non-failover strategy is a no-op (no panic).
	(&proxyPool{strategy: "round_robin"}).markFailed()
	(*proxyPool)(nil).markFailed()
}

func TestBuildResolverAndDialer(t *testing.T) {
	if buildResolver(nil) != nil {
		t.Error("no servers -> nil resolver (system default)")
	}
	if buildResolver([]string{"1.1.1.1", "8.8.8.8:53"}) == nil {
		t.Error("expected custom resolver")
	}
	d := newDialer([]string{"1.1.1.1"}, 3*time.Second)
	if d == nil || d.Resolver == nil {
		t.Error("dialer should carry a custom resolver")
	}
	if newDialer(nil, time.Second).Resolver != nil {
		t.Error("no resolvers -> default resolver (nil)")
	}
}
