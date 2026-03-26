package transport

import (
	"crypto/tls"
	"math/rand"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// TLSProfile defines a set of acceptable utls ClientHello IDs for a given browser family.
type TLSProfile struct {
	Name    string
	Hellos  []utls.ClientHelloID
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
	"random": {
		Name: "random",
		Hellos: []utls.ClientHelloID{
			utls.HelloRandomized,
			utls.HelloRandomizedNoALPN,
			utls.HelloRandomizedALPN,
		},
	},
}

// GetTLSProfile returns a random ClientHelloID corresponding to the requested browser family.
func GetTLSProfile(profile string, rng *rand.Rand) utls.ClientHelloID {
	profile = strings.ToLower(profile)
	if profile == "none" || profile == "" {
		// Fallback to strict randomized if custom TLS is disabled but somehow called.
		return utls.HelloRandomized
	}

	p, ok := tlsProfiles[profile]
	if !ok {
		p = tlsProfiles["random"]
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
