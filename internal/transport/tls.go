package transport

import (
	"crypto/tls"
	"math/rand"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// TLSProfile defines a set of acceptable utls ClientHello IDs for a given browser family.
type TLSProfile struct {
	Name   string
	Hellos []utls.ClientHelloID
}

var tlsProfiles = map[string]TLSProfile{
	"chrome": {
		Name: "chrome",
		Hellos: []utls.ClientHelloID{
			utls.HelloChrome_133,
			utls.HelloChrome_131,
			utls.HelloChrome_120,
			utls.HelloChrome_115_PQ,
		},
	},
	"firefox": {
		Name: "firefox",
		Hellos: []utls.ClientHelloID{
			utls.HelloFirefox_120,
			utls.HelloFirefox_105,
			utls.HelloFirefox_102,
			utls.HelloFirefox_99,
		},
	},
	"safari": {
		Name: "safari",
		Hellos: []utls.ClientHelloID{
			utls.HelloSafari_16_0,
			utls.HelloIOS_14,
			utls.HelloIOS_13,
		},
	},
	"edge": {
		Name: "edge",
		Hellos: []utls.ClientHelloID{
			utls.HelloEdge_106,
			utls.HelloEdge_85,
		},
	},
}

// realBrowserFamilies are the profiles used by the "random" rotation. They are
// chosen for reliability:
//   - Raw randomized ClientHellos are excluded — variants like
//     HelloRandomizedNoALPN omit ALPN, so the server replies in HTTP/1.1 while
//     the h2 transport insists on h2, erroring every request.
//   - Safari/iOS is excluded from the *random* pool because the current uTLS
//     Safari hellos fail the TLS 1.3 CertificateVerify step against ECDSA-cert
//     hosts (very common on CDNs). It stays explicitly selectable via
//     --tls-impersonate safari for RSA-cert targets.
var realBrowserFamilies = []string{"chrome", "firefox", "edge"}

// GetTLSProfile returns a ClientHelloID for the requested browser family.
//   - "random" picks a random *real* browser (all of which negotiate ALPN),
//   - "none"/"" still needs a concrete hello for the uTLS transport, so it uses
//     a stable, ALPN-safe Chrome fingerprint.
func GetTLSProfile(profile string, rng *rand.Rand) utls.ClientHelloID {
	profile = strings.ToLower(profile)
	switch profile {
	case "none", "":
		return utls.HelloChrome_120
	case "random":
		profile = realBrowserFamilies[rng.Intn(len(realBrowserFamilies))]
	}

	p, ok := tlsProfiles[profile]
	if !ok {
		p = tlsProfiles["chrome"]
	}

	return p.Hellos[rng.Intn(len(p.Hellos))]
}

// BuildUTLSConfig constructs a utls.Config. It intentionally skips verification
// for offensive security scanning. ALPN is handled by utls automatically based
// on the ClientHelloID and http2 settings.
func BuildUTLSConfig(serverName string) *utls.Config {
	return &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
}
