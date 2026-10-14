package aibouncer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// IPRangeList is a parsed list of IP prefixes published by a crawler operator.
type IPRangeList struct {
	Prefixes []netip.Prefix
	// CreationTime is the list's own "creationTime" field when present, otherwise zero.
	CreationTime time.Time
}

// ErrNoPrefixes is returned when a document contains no IP prefixes at all.
var ErrNoPrefixes = errors.New("aibouncer: no IP prefixes found")

// ParseIPRanges parses an operator's published IP range list.
//
// It understands the {"creationTime": ..., "prefixes": [{"ipv4Prefix": ...}, {"ipv6Prefix": ...}]}
// shape used by Google, Microsoft, OpenAI, Perplexity and others; for any other JSON document it
// collects every string that parses as a CIDR prefix or IP address. Non-JSON input is read as
// HTML or text containing JSON fragments (Amazon publishes its lists inside HTML pages): values of
// the "ipv4Prefix", "ipv6Prefix", "ip_prefix" and "ipv6_prefix" keys are extracted, and only
// those, so version numbers or other IP-shaped strings on the page are never picked up. Anything
// else is read as plain text with one prefix or address per line ('#' starts a comment).
// Prefixes are masked and de-duplicated.
func ParseIPRanges(data []byte) (IPRangeList, error) {
	var list IPRangeList
	trimmed := bytes.TrimSpace(data)

	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var document any
		if err := json.Unmarshal(trimmed, &document); err != nil {
			return list, err
		}
		collectPrefixes(document, &list.Prefixes)
		if object, ok := document.(map[string]any); ok {
			if created, ok := object["creationTime"].(string); ok {
				list.CreationTime = parseCreationTime(created)
			}
		}
	} else if embedded := embeddedPrefixes(trimmed); len(embedded) > 0 {
		list.Prefixes = embedded
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(trimmed))
		for scanner.Scan() {
			line, _, _ := strings.Cut(scanner.Text(), "#")
			if prefix, ok := parsePrefix(strings.TrimSpace(line)); ok {
				list.Prefixes = append(list.Prefixes, prefix)
			}
		}
		if err := scanner.Err(); err != nil {
			return list, err
		}
	}

	list.Prefixes = dedupePrefixes(list.Prefixes)
	if len(list.Prefixes) == 0 {
		return list, ErrNoPrefixes
	}
	return list, nil
}

// embeddedPrefixKey matches "ipv4Prefix": "192.0.2.0/24" with plain or HTML-escaped quotes.
var embeddedPrefixKey = regexp.MustCompile(`(?:"|&quot;|&#34;)(?:ipv4Prefix|ipv6Prefix|ip_prefix|ipv6_prefix)(?:"|&quot;|&#34;)\s*:\s*(?:"|&quot;|&#34;)([0-9A-Fa-f:./]+)(?:"|&quot;|&#34;)`)

func embeddedPrefixes(data []byte) []netip.Prefix {
	var out []netip.Prefix
	for _, match := range embeddedPrefixKey.FindAllSubmatch(data, -1) {
		if prefix, ok := parsePrefix(string(match[1])); ok {
			out = append(out, prefix)
		}
	}
	return out
}

func collectPrefixes(node any, out *[]netip.Prefix) {
	switch value := node.(type) {
	case map[string]any:
		for _, child := range value {
			collectPrefixes(child, out)
		}
	case []any:
		for _, child := range value {
			collectPrefixes(child, out)
		}
	case string:
		if prefix, ok := parsePrefix(value); ok {
			*out = append(*out, prefix)
		}
	}
}

func parsePrefix(s string) (netip.Prefix, bool) {
	if s == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		if prefix.Addr().Is4In6() {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		return prefix.Masked(), prefix.IsValid()
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func parseCreationTime(s string) time.Time {
	layouts := []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05", "2006-01-02"}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func dedupePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	sort.Slice(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	out := prefixes[:0]
	for i, prefix := range prefixes {
		if i > 0 && prefix == prefixes[i-1] {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// prefixSet answers membership queries for a list of prefixes.
type prefixSet struct {
	v4, v6 []netip.Prefix
}

func newPrefixSet(prefixes []netip.Prefix) prefixSet {
	var set prefixSet
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			set.v4 = append(set.v4, prefix)
		} else {
			set.v6 = append(set.v6, prefix)
		}
	}
	return set
}

func (s prefixSet) contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	candidates := s.v6
	if addr.Is4() {
		candidates = s.v4
	}
	for _, prefix := range candidates {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s prefixSet) len() int { return len(s.v4) + len(s.v6) }
