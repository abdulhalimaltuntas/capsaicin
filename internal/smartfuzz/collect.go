package smartfuzz

import (
	"regexp"
	"strings"
)

// collectPathRe pulls path-like and identifier-like tokens out of a response
// body: href/src targets, quoted JS string paths, and bare directory names.
var (
	collectQuotedPathRe = regexp.MustCompile(`["'` + "`" + `](/?[a-zA-Z0-9_][a-zA-Z0-9_\-./]{1,60})["'` + "`" + `]`)
	collectWordRe       = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9_\-]{2,30}`)
	collectExtRe        = regexp.MustCompile(`\.[a-zA-Z0-9]{1,6}$`)
)

// CollectWords mines a response body for new fuzzing candidates: it harvests path
// segments and identifiers that commonly map to real endpoints, filtering out
// HTML/JS noise. The returned slice is deduplicated and bounded so a single large
// page cannot flood the queue. This powers adaptive "learn-as-you-scan" fuzzing.
func CollectWords(body string, limit int) []string {
	if limit <= 0 {
		limit = 200
	}
	seen := make(map[string]bool)
	var out []string

	push := func(w string) bool {
		w = strings.Trim(strings.TrimSpace(w), "/")
		if w == "" || len(w) > 60 || seen[w] {
			return true
		}
		if isCommonHTMLKeyword(strings.ToLower(w)) || isBoringWord(w) {
			return true
		}
		seen[w] = true
		out = append(out, w)
		return len(out) < limit
	}

	// 1. Quoted paths (JS route tables, fetch() targets, anchor hrefs).
	for _, m := range collectQuotedPathRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		raw := m[1]
		// Split into segments; each meaningful segment is a fuzz candidate.
		for _, seg := range strings.Split(raw, "/") {
			seg = strings.TrimSpace(seg)
			if seg == "" || strings.ContainsAny(seg, "{}<>:") {
				continue
			}
			// Skip pure version/asset hashes and query fragments.
			if collectExtRe.MatchString(seg) && isAssetExt(seg) {
				continue
			}
			if !push(seg) {
				return out
			}
		}
	}

	// 2. Bare identifiers from visible text (lower-signal; only when we still
	// have budget) — captures things like "dashboard", "invoices", "webhook".
	if len(out) < limit {
		for _, w := range collectWordRe.FindAllString(body, -1) {
			lw := strings.ToLower(w)
			if isCommonHTMLKeyword(lw) || isBoringWord(w) {
				continue
			}
			if !push(lw) {
				return out
			}
		}
	}

	return out
}

// isAssetExt reports whether a segment ends in a static-asset extension that is
// not worth fuzzing as a directory name.
func isAssetExt(seg string) bool {
	lower := strings.ToLower(seg)
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
		".svg", ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp", ".mp4"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// boringWords are high-frequency, low-signal tokens that pollute the learned set.
var boringWords = map[string]bool{
	"http": true, "https": true, "www": true, "com": true, "org": true,
	"net": true, "the": true, "and": true, "for": true, "with": true,
	"this": true, "that": true, "from": true, "your": true, "you": true,
	"are": true, "was": true, "has": true, "have": true, "all": true,
	"can": true, "will": true, "our": true, "not": true, "but": true,
}

func isBoringWord(w string) bool {
	return boringWords[strings.ToLower(w)]
}
