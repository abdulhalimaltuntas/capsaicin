// Package wordlist ships curated, embedded wordlists so Capsaicin runs with zero
// external files — `capsaicin -u host` just works. Lists are compiled into the
// binary via go:embed and exposed by name.
package wordlist

import (
	_ "embed"
	"sort"
	"strings"
)

//go:embed data/common.txt
var commonRaw string

//go:embed data/params.txt
var paramsRaw string

// Names of the built-in lists selectable via --builtin.
const (
	Common = "common"
	Params = "params"
)

// Get returns the named built-in list, or nil if the name is unknown.
func Get(name string) []string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case Common, "":
		return parse(commonRaw)
	case Params:
		return parse(paramsRaw)
	default:
		return nil
	}
}

// Names lists the available built-in wordlist names.
func Names() []string {
	return []string{Common, Params}
}

// parse turns embedded text into a trimmed, comment-free, deduplicated slice.
func parse(raw string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}

// Sorted returns a copy of a list in lexical order (stable, diffable output).
func Sorted(list []string) []string {
	out := make([]string, len(list))
	copy(out, list)
	sort.Strings(out)
	return out
}
