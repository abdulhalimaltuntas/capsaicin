package detection

import (
	"encoding/base64"
	"strings"
)

// FaviconHash computes the MurmurHash3 (x86, 32-bit, signed) of a favicon using
// Shodan's exact encoding (standard base64 wrapped at 76 columns with a trailing
// newline). The resulting integer is the value you pivot on with
// `http.favicon.hash:<n>` on Shodan or Censys to find related hosts.
func FaviconHash(favicon []byte) int32 {
	if len(favicon) == 0 {
		return 0
	}
	return int32(mmh3x86_32([]byte(shodanBase64(favicon)), 0))
}

func shodanBase64(data []byte) string {
	raw := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		b.WriteString(raw[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}

// mmh3x86_32 is the MurmurHash3 x86 32-bit hash.
func mmh3x86_32(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data)
	nblocks := n / 4

	for i := 0; i < nblocks; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}

	var k uint32
	tail := data[nblocks*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}

	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// FaviconProduct maps well-known favicon hashes to a product/technology label.
// Kept intentionally small and high-confidence; an unknown hash is still useful
// as a raw Shodan/Censys pivot, so callers should report the number regardless.
var faviconProducts = map[int32]string{
	116323821:   "GitLab",
	-1255347784: "Jenkins",
	81586312:    "phpMyAdmin",
	-1273211170: "Grafana",
}

// FaviconProduct returns a product label for a favicon hash, or "" if unknown.
func FaviconProduct(hash int32) string { return faviconProducts[hash] }
