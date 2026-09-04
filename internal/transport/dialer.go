package transport

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// buildResolver returns a *net.Resolver that round-robins the supplied DNS
// servers (host or host:port; :53 assumed). Returns nil to use the system
// resolver when no servers are configured.
func buildResolver(servers []string) *net.Resolver {
	norm := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		norm = append(norm, s)
	}
	if len(norm) == 0 {
		return nil
	}

	var idx uint64
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			server := norm[int(atomic.AddUint64(&idx, 1))%len(norm)]
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, server)
		},
	}
}

// newDialer builds the base TCP dialer, wiring custom resolvers when provided.
func newDialer(resolvers []string, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if r := buildResolver(resolvers); r != nil {
		d.Resolver = r
	}
	return d
}
