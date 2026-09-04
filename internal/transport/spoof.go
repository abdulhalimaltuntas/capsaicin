package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
)

// dispatchTransport makes uTLS JA3/JA4 impersonation correct across every scheme
// and negotiated protocol, instead of forcing HTTP/2 onto connections that can't
// speak it:
//
//   - http://  → HTTP/1.1 (cleartext); the h2 transport cannot do cleartext.
//   - https:// → HTTP/2 first; if the peer only offers HTTP/1.1 (ALPN), the
//     request transparently falls back to the uTLS HTTP/1.1 transport.
//
// Both branches share the same spoofed ClientHello, so the TLS fingerprint is
// identical regardless of which path a given target ends up using.
type dispatchTransport struct {
	h2 http.RoundTripper
	h1 http.RoundTripper
}

func (d *dispatchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return d.h1.RoundTrip(req)
	}
	resp, err := d.h2.RoundTrip(req)
	if err != nil && errors.Is(err, ErrH2NotNegotiated) {
		return d.h1.RoundTrip(req)
	}
	return resp, err
}

// newUTLSH1Transport builds a standard HTTP/1.1 transport that still performs the
// spoofed uTLS ClientHello on https, and dials http:// normally. It is used both
// for cleartext targets and as the HTTP/1.1 fallback under --h2. The shared
// dialer carries any custom --resolvers; sni overrides the TLS server name.
func newUTLSH1Transport(
	helloID utls.ClientHelloID,
	proxyFunc func(*http.Request) (*url.URL, error),
	dialer *net.Dialer,
	sni string,
) *http.Transport {
	return &http.Transport{
		Proxy:                 proxyFunc,
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           dialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			if sni != "" {
				host = sni
			}
			raw, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			uConn := utls.UClient(raw, &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
			}, helloID)
			if err := uConn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return uConn, nil
		},
	}
}
