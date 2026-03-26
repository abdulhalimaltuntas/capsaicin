package transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// H2TransportBuilder manages the construction of a highly optimized HTTP/2 transport
// that uses utls for the underlying TLS connection.
type H2TransportBuilder struct {
	DialTimeout time.Duration
	TLSConfig   *utls.Config
	HelloID     utls.ClientHelloID
	ProxyFunc   func(*http.Request) (*url.URL, error)
	Dialer      *net.Dialer
}

// NewH2TransportBuilder initializes the builder with aggressive fuzzing defaults.
func NewH2TransportBuilder() *H2TransportBuilder {
	return &H2TransportBuilder{
		DialTimeout: 10 * time.Second,
		Dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

// Build constructs the custom h2 transport using utls for spoofing.
func (b *H2TransportBuilder) Build() (*http2.Transport, error) {
	// Custom DialTLS context function that intercepts the raw TCP dial,
	// wraps it in utls.UClient, and forces the handshake with the spoofed ID.
	dialTLS := func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		// Dial raw TCP.
		conn, err := b.Dialer.Dial(network, addr)
		if err != nil {
			return nil, err
		}

		// Clone the provided TLS config to avoid concurrent mutation.
		uCfg := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		}
		if cfg != nil {
			uCfg.NextProtos = cfg.NextProtos
		}

		// Initialize the uTLS client.
		uConn := utls.UClient(conn, uCfg, b.HelloID)

		// Force the handshake. If it fails, clean up the underlying socket.
		if err := uConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("utls handshake failed indicating WAF drop or timeout: %w", err)
		}

		// Verify ALPN negotiation for HTTP/2. Severe strict WAFs might downgrade us.
		if uConn.ConnectionState().NegotiatedProtocol != "h2" {
			// Some WAFs aggressively close the connection if they don't like the ALPN.
			// We return the connection anyway; the http2 package will typically fail fast if it's not actually h2.
		}

		return uConn, nil
	}

	// High concurrency HTTP/2 settings to avoid SYN floods.
	t2 := &http2.Transport{
		DialTLS:            dialTLS,
		AllowHTTP:          false, // Force TLS.
		MaxReadFrameSize:   1048576,
		DisableCompression: true, // Let the application layer handle it.
		PingTimeout:        5 * time.Second,
		ReadIdleTimeout:    30 * time.Second,
		StrictMaxConcurrentStreams: false, // Don't choke our own queue if the server signals strict limits, queue instead.
	}

	return t2, nil
}
