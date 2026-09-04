package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ErrH2NotNegotiated is returned by the uTLS dialer when the peer completes the
// handshake without selecting HTTP/2 via ALPN. The dispatch transport treats it
// as a signal to retry the request over HTTP/1.1 instead of surfacing an error.
var ErrH2NotNegotiated = errors.New("utls: peer did not negotiate HTTP/2 (ALPN)")

// H2TransportBuilder manages the construction of a highly optimized HTTP/2 transport
// that uses utls for the underlying TLS connection.
type H2TransportBuilder struct {
	DialTimeout time.Duration
	TLSConfig   *utls.Config
	HelloID     utls.ClientHelloID
	ProxyFunc   func(*http.Request) (*url.URL, error)
	Dialer      *net.Dialer
	SNI         string // TLS SNI override; empty = use the dialed host
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

		serverName := host
		if b.SNI != "" {
			serverName = b.SNI
		}
		// Clone the provided TLS config to avoid concurrent mutation.
		uCfg := &utls.Config{
			ServerName:         serverName,
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

		// Verify ALPN negotiation for HTTP/2. If the peer did not choose h2
		// (plain HTTP/1.1 server, or a WAF that downgraded us), handing the
		// connection to the http2 transport would corrupt every request with a
		// framing error. Signal a clean fallback instead.
		if uConn.ConnectionState().NegotiatedProtocol != "h2" {
			uConn.Close()
			return nil, ErrH2NotNegotiated
		}

		return uConn, nil
	}

	// High concurrency HTTP/2 settings to avoid SYN floods.
	t2 := &http2.Transport{
		DialTLS:                    dialTLS,
		AllowHTTP:                  false, // Force TLS.
		MaxReadFrameSize:           1048576,
		DisableCompression:         true, // Let the application layer handle it.
		PingTimeout:                5 * time.Second,
		ReadIdleTimeout:            30 * time.Second,
		StrictMaxConcurrentStreams: false, // Don't choke our own queue if the server signals strict limits, queue instead.
	}

	return t2, nil
}
