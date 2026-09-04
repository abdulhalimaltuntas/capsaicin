package transport

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// H3TransportBuilder constructs an HTTP/3 (QUIC) RoundTripper.
//
// HTTP/3 runs over UDP and cannot be tunnelled through a SOCKS/HTTP CONNECT
// proxy, so the builder deliberately ignores proxy configuration — the config
// layer rejects the --h3 + SOCKS combination before we get here.
type H3TransportBuilder struct {
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	ServerName       string
}

// NewH3TransportBuilder returns a builder with conservative QUIC timeouts.
func NewH3TransportBuilder() *H3TransportBuilder {
	return &H3TransportBuilder{
		HandshakeTimeout: 5 * time.Second,
		IdleTimeout:      30 * time.Second,
	}
}

// Build returns an http.RoundTripper speaking HTTP/3, plus a closer that
// releases the QUIC session pool when the scan ends.
func (b *H3TransportBuilder) Build() (http.RoundTripper, func() error, error) {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			// Fuzzing targets frequently present invalid or self-signed certs;
			// verification is intentionally skipped, mirroring the H2 path.
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
			ServerName:         b.ServerName, // empty = per-connection default
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: b.HandshakeTimeout,
			MaxIdleTimeout:       b.IdleTimeout,
			KeepAlivePeriod:      15 * time.Second,
		},
	}
	return tr, tr.Close, nil
}
