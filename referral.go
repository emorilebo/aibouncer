package aibouncer

import (
	"net/http"
	"net/url"
	"strings"
)

// Referral describes a human visit that arrived from an AI assistant.
type Referral struct {
	// Assistant is the assistant's name, e.g. "ChatGPT" or "Perplexity".
	Assistant string
	// Signal is how the referral was recognised: "utm_source" or "referer".
	Signal string
	// Value is the matching utm_source value or Referer host.
	Value string
	// Evidence is "official" if the assistant's operator documents the signal, otherwise
	// "reputable-observed".
	Evidence string
}

// DetectReferral reports whether the request is a click-through from an AI assistant. The
// utm_source query parameter is checked first because it survives Referer-stripping browsers
// and apps; the Referer header is checked second.
//
// Many assistants strip or omit both signals (native apps in particular), so referral counts
// are a lower bound, never a census.
func (c *Catalog) DetectReferral(r *http.Request) (Referral, bool) {
	if r.URL != nil {
		if utm := r.URL.Query().Get("utm_source"); utm != "" {
			utm = strings.ToLower(utm)
			for _, source := range c.Referrals {
				for _, value := range source.UTMSources {
					if utm == strings.ToLower(value) {
						return Referral{Assistant: source.Assistant, Signal: "utm_source", Value: utm, Evidence: source.Evidence}, true
					}
				}
			}
		}
	}
	return c.DetectReferer(r.Referer())
}

// DetectReferer matches a Referer URL against known AI assistant hosts. A host matches itself
// and its subdomains ("www.perplexity.ai" matches "perplexity.ai"); entries with a path, such as
// "x.com/i/grok", also require the path prefix.
func (c *Catalog) DetectReferer(referer string) (Referral, bool) {
	if referer == "" {
		return Referral{}, false
	}
	u, err := url.Parse(referer)
	if err != nil || u.Host == "" {
		return Referral{}, false
	}
	host := strings.ToLower(u.Hostname())
	for _, source := range c.Referrals {
		for _, entry := range source.Hosts {
			entryHost, entryPath, hasPath := strings.Cut(strings.ToLower(entry), "/")
			if host != entryHost && !strings.HasSuffix(host, "."+entryHost) {
				continue
			}
			if hasPath && !strings.HasPrefix(u.EscapedPath(), "/"+entryPath) {
				continue
			}
			return Referral{Assistant: source.Assistant, Signal: "referer", Value: host, Evidence: source.Evidence}, true
		}
	}
	return Referral{}, false
}
