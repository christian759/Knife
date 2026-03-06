package scanners

import (
	"regexp"
	"strings"
)

func snippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func snippetAround(s, match string, maxLen int) string {
	loc := strings.Index(s, match)
	if loc == -1 {
		return snippet(s, maxLen)
	}
	start := loc - maxLen/2
	if start < 0 {
		start = 0
	}
	end := start + maxLen
	if end > len(s) {
		end = len(s)
	}
	sn := s[start:end]
	if start > 0 {
		sn = "…" + sn
	}
	if end < len(s) {
		sn = sn + "…"
	}
	return sn
}

func findRegexSnippet(re *regexp.Regexp, s string, maxLen int) string {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return snippet(s, maxLen)
	}
	start := loc[0] - maxLen/2
	if start < 0 {
		start = 0
	}
	end := start + maxLen
	if end > len(s) {
		end = len(s)
	}
	sn := s[start:end]
	if start > 0 {
		sn = "…" + sn
	}
	if end < len(s) {
		sn = sn + "…"
	}
	return sn
}
