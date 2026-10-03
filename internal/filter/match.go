package filter

import "regexp"

var cache = map[string]*regexp.Regexp{}

// matchHere compiles once and matches; filter expressions are few.
func matchHere(expr, s string) bool {
	re := cache[expr]
	if re == nil {
		var err error
		re, err = regexp.Compile(expr)
		if err != nil {
			return false
		}
		cache[expr] = re
	}
	return re.MatchString(s)
}

func quote(lit string) string { return regexp.QuoteMeta(lit) }
