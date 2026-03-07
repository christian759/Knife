package scanners

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

func normalizeSubtype(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func containsAnyFold(s string, terms ...string) bool {
	s = strings.ToLower(s)
	for _, t := range terms {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

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

// finalizeQueryPayloads deduplicates payloads and adds evasive encodings for higher intensity scans.
func finalizeQueryPayloads(payloads []string, intensity int) []string {
	out := make([]string, 0, len(payloads)*3)
	for _, p := range payloads {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
		if intensity >= 3 {
			out = append(out, url.QueryEscape(p))
		}
		if intensity >= 4 {
			out = append(out, strings.ReplaceAll(p, " ", "${IFS}"))
			out = append(out, strings.ReplaceAll(url.QueryEscape(p), "%", "%25"))
		}
	}
	return dedupeStrings(out)
}

// finalizeBodyPayloads deduplicates payloads and adds whitespace/encoding variants for deeper scans.
func finalizeBodyPayloads(payloads []string, intensity int) []string {
	out := make([]string, 0, len(payloads)*3)
	for _, p := range payloads {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
		if intensity >= 3 {
			out = append(out, strings.ReplaceAll(p, " ", "\t"))
		}
		if intensity >= 4 {
			out = append(out, strings.ReplaceAll(p, " ", "\n"))
		}
	}
	return dedupeStrings(out)
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		k := strings.TrimSpace(item)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func buildFindingKey(parts ...string) string {
	norm := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		norm = append(norm, p)
	}
	return strings.Join(norm, "|")
}
