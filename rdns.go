package aibouncer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Resolver is the subset of *net.Resolver used for reverse-DNS verification.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// forwardConfirmedReverseDNS implements the verification procedure search engines document:
// resolve the IP to host names, keep names under one of the operator's domains, then resolve
// those names forward and require the original IP among the results. A PTR record alone proves
// nothing, since whoever controls an IP block controls its reverse zone.
func forwardConfirmedReverseDNS(ctx context.Context, resolver Resolver, addr netip.Addr, suffixes []string) (bool, error) {
	names, err := resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	var lastErr error
	for _, name := range names {
		host := strings.ToLower(strings.TrimSuffix(name, "."))
		if !hasDomainSuffix(host, suffixes) {
			continue
		}
		forward, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			lastErr = err
			continue
		}
		for _, candidate := range forward {
			if candidate.Unmap() == addr.Unmap() {
				return true, nil
			}
		}
	}
	if lastErr != nil && !isNotFound(lastErr) {
		return false, lastErr
	}
	return false, nil
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// hasDomainSuffix reports whether host equals one of the suffixes or is a subdomain of one.
// "crawl-66-249-66-1.googlebot.com" matches "googlebot.com"; "evilgooglebot.com" does not.
func hasDomainSuffix(host string, suffixes []string) bool {
	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.TrimPrefix(suffix, "."))
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// dnsCache remembers reverse-DNS verdicts. It is bounded so that a scraper rotating through
// thousands of addresses cannot grow memory without limit; when full, expired entries are
// dropped first and then an arbitrary entry is evicted.
type dnsCache struct {
	mu       sync.Mutex
	entries  map[dnsCacheKey]dnsCacheEntry
	capacity int
}

type dnsCacheKey struct {
	agentID string
	addr    netip.Addr
}

type dnsCacheEntry struct {
	verified bool
	expires  time.Time
}

func newDNSCache(capacity int) *dnsCache {
	return &dnsCache{entries: make(map[dnsCacheKey]dnsCacheEntry), capacity: capacity}
}

func (c *dnsCache) get(key dnsCacheKey, now time.Time) (verified, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || now.After(entry.expires) {
		return false, false
	}
	return entry.verified, true
}

func (c *dnsCache) put(key dnsCacheKey, verified bool, expires, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.capacity {
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
		for k := range c.entries {
			if len(c.entries) < c.capacity {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[key] = dnsCacheEntry{verified: verified, expires: expires}
}
