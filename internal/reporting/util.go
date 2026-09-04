package reporting

import (
	"strconv"
	"unicode"
)

func itoa(n int) string { return strconv.Itoa(n) }

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// titleCase upper-cases the first rune of s (a non-deprecated stand-in for the
// single-word use of the removed strings.Title).
func titleCase(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
