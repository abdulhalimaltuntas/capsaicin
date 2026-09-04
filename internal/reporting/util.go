package reporting

import "strconv"

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
