package scanner

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/abdulhalimaltuntas/capsaicin/internal/config"
)

// Matcher decides whether a response is surfaced as a finding, implementing the
// ffuf-style matcher/filter model that the -mc/-ms/-mr/-fc/-fs/-fw flags expose.
//
// Semantics:
//   - Filters (fc/fs/fw) exclude: any match drops the response.
//   - Matchers (mc/ms/mr) include: an *active* matcher must match; an unset
//     matcher passes automatically.
//   - Filters are evaluated first and take precedence over matchers.
type Matcher struct {
	matchCodes  *numSet
	matchSize   *numSet
	matchRegex  *regexp.Regexp
	filterCodes *numSet
	filterSize  *numSet
	filterWords *numSet
}

// NewMatcher builds a Matcher from the resolved config. It only errors on an
// invalid --match-regex (already validated upstream, checked here for safety).
func NewMatcher(cfg config.Config) (*Matcher, error) {
	m := &Matcher{
		matchCodes:  parseNumSet(cfg.MatchCodes),
		matchSize:   parseNumSet(cfg.MatchSize),
		filterCodes: parseNumSet(cfg.FilterCodes),
		filterSize:  parseNumSet(cfg.FilterSize),
		filterWords: parseNumSet(cfg.FilterWords),
	}
	if cfg.MatchRegex != "" {
		re, err := regexp.Compile(cfg.MatchRegex)
		if err != nil {
			return nil, err
		}
		m.matchRegex = re
	}
	return m, nil
}

// Keep reports whether a response should be surfaced as a finding.
func (m *Matcher) Keep(status, size, words int, body string) bool {
	// Filters take precedence — any hit excludes the response.
	if m.filterCodes.active() && m.filterCodes.has(status) {
		return false
	}
	if m.filterSize.active() && m.filterSize.has(size) {
		return false
	}
	if m.filterWords.active() && m.filterWords.has(words) {
		return false
	}

	// Active matchers must all match; unset matchers pass.
	if m.matchCodes.active() && !m.matchCodes.has(status) {
		return false
	}
	if m.matchSize.active() && !m.matchSize.has(size) {
		return false
	}
	if m.matchRegex != nil && !m.matchRegex.MatchString(body) {
		return false
	}
	return true
}

// numSet is a set of integers expressed as a comma-separated spec of exact
// values and lo-hi ranges (e.g. "200-299,301,302,404").
type numSet struct {
	ranges []intRange
	exact  map[int]bool
	set    bool
}

type intRange struct{ lo, hi int }

func parseNumSet(spec string) *numSet {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return &numSet{}
	}
	ns := &numSet{exact: make(map[int]bool)}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			b := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(b[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(b[1]))
			if e1 == nil && e2 == nil {
				ns.ranges = append(ns.ranges, intRange{lo, hi})
				ns.set = true
			}
		} else if n, err := strconv.Atoi(part); err == nil {
			ns.exact[n] = true
			ns.set = true
		}
	}
	return ns
}

func (ns *numSet) active() bool { return ns != nil && ns.set }

func (ns *numSet) has(v int) bool {
	if ns == nil || !ns.set {
		return false
	}
	if ns.exact[v] {
		return true
	}
	for _, r := range ns.ranges {
		if v >= r.lo && v <= r.hi {
			return true
		}
	}
	return false
}
