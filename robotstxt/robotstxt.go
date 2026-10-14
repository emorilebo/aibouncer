// Package robotstxt parses robots.txt files and answers the question "may this crawler fetch
// this path?" following RFC 9309, the Robots Exclusion Protocol.
//
// It implements the parts of the RFC that decide access: product-token group matching
// (case-insensitive, with a "*" fallback and merging of repeated groups), longest-match
// precedence between allow and disallow rules (allow wins ties), the "*" and "$" special
// characters, percent-encoding normalisation, the 500 KiB parsing limit, and the implicit
// allow of /robots.txt itself. Fetching, redirects and caching are left to the caller; see
// [StatusPolicy] for how HTTP status codes map to access decisions.
package robotstxt

import (
	"bytes"
	"strings"
)

// MaxSize is the number of bytes parsed. RFC 9309 section 2.5 requires crawlers to parse at
// least 500 KiB; content beyond that is ignored.
const MaxSize = 500 * 1024

// Rule is a single allow or disallow line.
type Rule struct {
	Allow   bool
	Pattern string
}

// Group is a set of rules that applies to one or more user agents.
type Group struct {
	UserAgents []string
	Rules      []Rule
}

// File is a parsed robots.txt.
type File struct {
	Groups   []Group
	Sitemaps []string
}

// Parse parses robots.txt content. It never fails: malformed lines are ignored, as the RFC
// requires parsers to be lenient.
func Parse(data []byte) *File {
	if len(data) > MaxSize {
		data = data[:MaxSize]
	}
	data = bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))

	file := &File{}
	var current *Group
	lastWasRule := false

	for _, rawLine := range splitLines(string(data)) {
		line := rawLine
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch key {
		case "user-agent":
			if current == nil || lastWasRule {
				file.Groups = append(file.Groups, Group{})
				current = &file.Groups[len(file.Groups)-1]
			}
			current.UserAgents = append(current.UserAgents, value)
			lastWasRule = false
		case "allow", "disallow":
			if current == nil {
				continue // rules before any user-agent line belong to no group
			}
			lastWasRule = true
			if value == "" {
				continue // an empty rule matches nothing
			}
			current.Rules = append(current.Rules, Rule{Allow: key == "allow", Pattern: value})
		case "sitemap":
			if value != "" {
				file.Sitemaps = append(file.Sitemaps, value)
			}
		}
	}
	return file
}

// Match describes how a crawler's access to a path was decided.
type Match struct {
	Allowed bool
	// Rule is the deciding rule, or nil if no rule matched (access is then allowed).
	Rule *Rule
	// Explicit reports whether a group names the crawler's product token directly, as opposed to
	// falling back to the "*" group (or to no group at all).
	Explicit bool
}

// Allowed reports whether the crawler identified by productToken (for example "GPTBot") may
// fetch path. Path should be the URL path including any query string, e.g. "/search?q=go".
func (f *File) Allowed(productToken, path string) bool {
	return f.Check(productToken, path).Allowed
}

// Check is like [File.Allowed] but also returns the deciding rule and whether the crawler was
// named explicitly.
func (f *File) Check(productToken, path string) Match {
	rules, explicit := f.rulesFor(productToken)
	match := Match{Allowed: true, Explicit: explicit}
	if path == "" {
		path = "/"
	}
	if path == "/robots.txt" {
		return match
	}

	normalizedPath := normalize(path)
	bestLength := -1
	for i := range rules {
		pattern := normalize(rules[i].Pattern)
		if !matchPattern(pattern, normalizedPath) {
			continue
		}
		length := len(pattern)
		if length > bestLength || (length == bestLength && rules[i].Allow && !match.Allowed) {
			bestLength = length
			match.Allowed = rules[i].Allow
			match.Rule = &rules[i]
		}
	}
	return match
}

// rulesFor merges every group that names the product token. If none does, the "*" groups are
// used. RFC 9309 section 2.2.1.
func (f *File) rulesFor(productToken string) (rules []Rule, explicit bool) {
	var wildcard []Rule
	for _, group := range f.Groups {
		for _, agent := range group.UserAgents {
			if agent == "*" {
				wildcard = append(wildcard, group.Rules...)
				continue
			}
			if strings.EqualFold(productTokenOf(agent), productToken) {
				rules = append(rules, group.Rules...)
				explicit = true
				break
			}
		}
	}
	if explicit {
		return rules, true
	}
	return wildcard, false
}

// productTokenOf extracts the leading product token from a user-agent line value, so values
// like "Googlebot/2.1" match "Googlebot". RFC 9309 limits tokens to letters, '_' and '-', but
// documented crawler tokens such as Ai2's "AI2Bot" contain digits, so digits are accepted too.
func productTokenOf(value string) string {
	end := 0
	for end < len(value) {
		c := value[end]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			end++
			continue
		}
		break
	}
	return value[:end]
}

// matchPattern reports whether pattern matches a prefix of path, where '*' matches any
// sequence of characters and a trailing '$' anchors the match to the end of path.
func matchPattern(pattern, path string) bool {
	if strings.HasSuffix(pattern, "$") {
		return wildcardMatch(pattern[:len(pattern)-1], path)
	}
	return wildcardMatch(pattern+"*", path) // unanchored rules are prefix matches
}

// wildcardMatch matches the whole of s against p, where '*' matches any sequence. It runs in
// O(len(p)*len(s)) worst case, so hostile patterns such as "/*a*a*a*a*b" cannot cause
// exponential backtracking.
func wildcardMatch(p, s string) bool {
	pi, si := 0, 0
	starP, starS := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			starP, starS = pi, si
			pi++
		case pi < len(p) && p[pi] == s[si]:
			pi++
			si++
		case starP >= 0:
			starS++
			pi, si = starP+1, starS
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// normalize applies RFC 3986 percent-encoding normalisation so that "/a%7eb", "/a~b" and
// "/café" compare correctly: escapes of unreserved characters are decoded, other escapes
// are upper-cased, and non-ASCII bytes are percent-encoded.
func normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			decoded := unhex(s[i+1])<<4 | unhex(s[i+2])
			if isUnreserved(decoded) {
				b.WriteByte(decoded)
			} else {
				b.WriteByte('%')
				b.WriteByte(upperHex(s[i+1]))
				b.WriteByte(upperHex(s[i+2]))
			}
			i += 2
		case c >= 0x80:
			const hexDigits = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0F])
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

// Availability describes what a crawler may do based on the HTTP outcome of fetching robots.txt.
type Availability int

const (
	// ApplyRules means the response body should be parsed and its rules applied (2xx).
	ApplyRules Availability = iota
	// AllowAll means robots.txt is "unavailable" and the crawler may access everything (4xx).
	AllowAll
	// DisallowAll means robots.txt is "unreachable" and the crawler must assume a complete
	// disallow (5xx or network error).
	DisallowAll
)

// StatusPolicy maps the final HTTP status code of a robots.txt fetch (after following up to five
// redirects) to an access decision, per RFC 9309 section 2.3.1. Pass 0 for a network error.
func StatusPolicy(statusCode int) Availability {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return ApplyRules
	case statusCode >= 400 && statusCode < 500:
		return AllowAll
	default:
		return DisallowAll
	}
}
