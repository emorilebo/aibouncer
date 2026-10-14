package aibouncer

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Version is the aibouncer release version.
const Version = "0.1.0"

// Verdict is the outcome of checking whether a request really comes from the agent it claims.
type Verdict int

const (
	// NotAI means the request does not claim to be a known AI agent.
	NotAI Verdict = iota
	// Verified means the claim was confirmed with the operator's published IP ranges,
	// forward-confirmed reverse DNS, or a valid Web Bot Auth signature.
	Verified
	// Spoofed means the operator publishes a way to verify the agent and the request failed it:
	// someone borrowed the agent's name.
	Spoofed
	// Unverifiable means the claim could not be checked: the operator publishes no verification
	// method, the IP data is missing or stale, or DNS failed. It is not evidence of spoofing.
	Unverifiable
)

func (v Verdict) String() string {
	switch v {
	case NotAI:
		return "not-ai"
	case Verified:
		return "verified"
	case Spoofed:
		return "spoofed"
	case Unverifiable:
		return "unverifiable"
	}
	return fmt.Sprintf("Verdict(%d)", int(v))
}

// MarshalText implements encoding.TextMarshaler.
func (v Verdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// Result explains a verdict.
type Result struct {
	Agent   *Agent
	Verdict Verdict
	// Method is how a verified agent was confirmed: "ip-ranges", "documented-cidr",
	// "reverse-dns" or "web-bot-auth". Empty otherwise.
	Method string
	// Reason is a short human-readable explanation.
	Reason string
}

//go:embed snapshot.json
var snapshotJSON []byte

// Snapshot is a saved copy of operators' published IP range lists.
type Snapshot struct {
	FetchedAt time.Time           `json:"fetched_at"`
	Lists     map[string][]string `json:"lists"`
}

// Verifier checks AI agent claims against operators' published IP ranges and reverse DNS.
//
// A new Verifier starts from an IP range snapshot embedded at release time, so it works
// immediately and offline. Call [Verifier.Run] (or [Verifier.Refresh]) to keep the lists
// current; once a list is older than the maximum age, misses against it are reported as
// [Unverifiable] instead of [Spoofed], so stale data fails open rather than blocking genuine
// crawlers. A Verifier is safe for concurrent use.
type Verifier struct {
	catalog     *Catalog
	client      *http.Client
	resolver    Resolver
	reverseDNS  bool
	maxAge      time.Duration
	dnsTimeout  time.Duration
	maxBodySize int64
	now         func() time.Time

	lists     atomic.Pointer[map[string]rangeList]
	refreshMu sync.Mutex
	dnsCache  *dnsCache
	inflight  singleflight
}

type rangeList struct {
	set       prefixSet
	fetchedAt time.Time
	live      bool
	lastError error
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithHTTPClient sets the client used to download IP range lists.
func WithHTTPClient(c *http.Client) VerifierOption { return func(v *Verifier) { v.client = c } }

// WithResolver sets the DNS resolver used for reverse-DNS verification.
func WithResolver(r Resolver) VerifierOption { return func(v *Verifier) { v.resolver = r } }

// WithReverseDNS enables or disables reverse-DNS verification (enabled by default). Disable it
// to keep DNS lookups out of the request path entirely; agents that can only be verified by DNS
// then come back Unverifiable.
func WithReverseDNS(enabled bool) VerifierOption { return func(v *Verifier) { v.reverseDNS = enabled } }

// WithMaxAge sets how old IP range data may be before misses stop counting as spoofing
// (default 7 days).
func WithMaxAge(d time.Duration) VerifierOption { return func(v *Verifier) { v.maxAge = d } }

// WithVerifierCatalog sets the catalog whose IP range URLs are refreshed (default: DefaultCatalog).
func WithVerifierCatalog(c *Catalog) VerifierOption { return func(v *Verifier) { v.catalog = c } }

// WithSnapshot replaces the embedded IP range snapshot, e.g. with one saved by the CLI.
func WithSnapshot(s Snapshot) VerifierOption {
	return func(v *Verifier) { v.lists.Store(listsFromSnapshot(s)) }
}

// WithClock overrides the time source. Intended for tests.
func WithClock(now func() time.Time) VerifierOption { return func(v *Verifier) { v.now = now } }

// NewVerifier returns a Verifier initialised from the embedded snapshot.
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		catalog:     DefaultCatalog(),
		client:      &http.Client{Timeout: 30 * time.Second},
		resolver:    net.DefaultResolver,
		reverseDNS:  true,
		maxAge:      7 * 24 * time.Hour,
		dnsTimeout:  2 * time.Second,
		maxBodySize: 16 << 20,
		now:         time.Now,
		dnsCache:    newDNSCache(10000),
	}
	var embedded Snapshot
	if err := json.Unmarshal(snapshotJSON, &embedded); err != nil {
		panic(fmt.Sprintf("aibouncer: embedded snapshot: %v", err))
	}
	v.lists.Store(listsFromSnapshot(embedded))
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func listsFromSnapshot(s Snapshot) *map[string]rangeList {
	lists := make(map[string]rangeList, len(s.Lists))
	for url, raw := range s.Lists {
		var prefixes []netip.Prefix
		for _, p := range raw {
			if prefix, ok := parsePrefix(p); ok {
				prefixes = append(prefixes, prefix)
			}
		}
		lists[url] = rangeList{set: newPrefixSet(prefixes), fetchedAt: s.FetchedAt}
	}
	return &lists
}

// VerifyIP checks whether addr belongs to agent using the operator's published IP ranges,
// documented CIDRs and, as a fallback, forward-confirmed reverse DNS.
func (v *Verifier) VerifyIP(ctx context.Context, agent *Agent, addr netip.Addr) Result {
	result := Result{Agent: agent}
	if agent == nil {
		result.Verdict = NotAI
		return result
	}
	if !addr.IsValid() {
		result.Verdict, result.Reason = Unverifiable, "client IP unknown"
		return result
	}
	if len(agent.IPRanges) == 0 && len(agent.SharedIPRanges) == 0 && len(agent.CIDRs) == 0 && len(agent.ReverseDNS) == 0 {
		result.Verdict = Unverifiable
		if agent.WebBotAuth != nil {
			result.Reason = "operator only supports Web Bot Auth signatures"
		} else {
			result.Reason = "operator publishes no IP ranges or reverse-DNS domains"
		}
		return result
	}
	addr = addr.Unmap()

	lists := *v.lists.Load()
	ipConclusive := true
	for _, url := range agent.IPRanges {
		list, ok := lists[url]
		if !ok || list.set.len() == 0 {
			ipConclusive = false
			continue
		}
		if list.set.contains(addr) {
			result.Verdict, result.Method = Verified, "ip-ranges"
			result.Reason = "IP is in " + url
			return result
		}
		if v.now().Sub(list.fetchedAt) > v.maxAge {
			ipConclusive = false
		}
	}
	for _, cidr := range agent.CIDRs {
		if prefix, ok := parsePrefix(cidr); ok && prefix.Contains(addr) {
			result.Verdict, result.Method = Verified, "documented-cidr"
			result.Reason = "IP is in documented range " + cidr
			return result
		}
	}
	sharedHit := false
	for _, url := range agent.SharedIPRanges {
		list, ok := lists[url]
		if !ok || list.set.len() == 0 || v.now().Sub(list.fetchedAt) > v.maxAge {
			ipConclusive = false
			continue
		}
		if list.set.contains(addr) {
			sharedHit = true
		}
	}
	const sharedReason = "IP is in a range the operator shares with its cloud customers, so it is plausible but not proof"

	if len(agent.ReverseDNS) > 0 && v.reverseDNS && v.resolver != nil {
		verified, err := v.reverseDNSCached(ctx, agent, addr)
		switch {
		case err != nil:
			result.Verdict, result.Reason = Unverifiable, "reverse DNS lookup failed: "+err.Error()
			return result
		case verified:
			result.Verdict, result.Method = Verified, "reverse-dns"
			result.Reason = "forward-confirmed reverse DNS matched the operator's domain"
			return result
		case sharedHit:
			result.Verdict, result.Reason = Unverifiable, sharedReason
			return result
		default:
			result.Verdict = Spoofed
			result.Reason = "IP is outside the published ranges and reverse DNS does not confirm the operator"
			return result
		}
	}

	if sharedHit {
		result.Verdict, result.Reason = Unverifiable, sharedReason
		return result
	}
	if !ipConclusive || (len(agent.IPRanges) == 0 && len(agent.SharedIPRanges) == 0 && len(agent.CIDRs) == 0) {
		result.Verdict, result.Reason = Unverifiable, "IP range data is missing or older than the maximum age"
		return result
	}
	result.Verdict, result.Reason = Spoofed, "IP is outside the operator's published ranges"
	return result
}

func (v *Verifier) reverseDNSCached(ctx context.Context, agent *Agent, addr netip.Addr) (bool, error) {
	key := dnsCacheKey{agentID: agent.ID, addr: addr}
	now := v.now()
	if verified, ok := v.dnsCache.get(key, now); ok {
		return verified, nil
	}
	value, err := v.inflight.do(key, func() (bool, error) {
		lookupCtx, cancel := context.WithTimeout(ctx, v.dnsTimeout)
		defer cancel()
		verified, err := forwardConfirmedReverseDNS(lookupCtx, v.resolver, addr, agent.ReverseDNS)
		if err != nil {
			return false, err
		}
		ttl := time.Hour
		if !verified {
			ttl = 15 * time.Minute
		}
		v.dnsCache.put(key, verified, now.Add(ttl), now)
		return verified, nil
	})
	return value, err
}

// SourceStatus describes one IP range list.
type SourceStatus struct {
	URL       string
	Prefixes  int
	FetchedAt time.Time
	// Live is true once the list has been downloaded by this Verifier (false for snapshot data).
	Live bool
	// LastError is the error from the most recent failed refresh, if any.
	LastError error
}

// Status reports the state of every IP range list, sorted by URL.
func (v *Verifier) Status() []SourceStatus {
	lists := *v.lists.Load()
	out := make([]SourceStatus, 0, len(lists))
	for url, list := range lists {
		out = append(out, SourceStatus{URL: url, Prefixes: list.set.len(), FetchedAt: list.fetchedAt, Live: list.live, LastError: list.lastError})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// Snapshot returns the current IP range data, for saving and later use with [WithSnapshot].
func (v *Verifier) Snapshot() Snapshot {
	lists := *v.lists.Load()
	s := Snapshot{Lists: make(map[string][]string, len(lists))}
	for url, list := range lists {
		if s.FetchedAt.IsZero() || list.fetchedAt.Before(s.FetchedAt) {
			s.FetchedAt = list.fetchedAt
		}
		for _, p := range append(append([]netip.Prefix{}, list.set.v4...), list.set.v6...) {
			s.Lists[url] = append(s.Lists[url], p.String())
		}
	}
	return s
}

// Refresh downloads every IP range list referenced by the catalog. Lists that fail to download
// or parse keep their previous data; the returned error joins all failures.
func (v *Verifier) Refresh(ctx context.Context) error {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	urls := map[string]bool{}
	for _, agent := range v.catalog.Agents {
		for _, url := range append(append([]string{}, agent.IPRanges...), agent.SharedIPRanges...) {
			urls[url] = true
		}
	}

	type fetched struct {
		url  string
		list IPRangeList
		err  error
	}
	results := make(chan fetched, len(urls))
	for url := range urls {
		go func(url string) {
			list, err := v.fetch(ctx, url)
			results <- fetched{url: url, list: list, err: err}
		}(url)
	}

	current := *v.lists.Load()
	next := make(map[string]rangeList, len(urls))
	for url, list := range current {
		next[url] = list
	}
	var errs []error
	for range urls {
		res := <-results
		if res.err != nil {
			previous := next[res.url]
			previous.lastError = res.err
			next[res.url] = previous
			errs = append(errs, fmt.Errorf("%s: %w", res.url, res.err))
			continue
		}
		next[res.url] = rangeList{set: newPrefixSet(res.list.Prefixes), fetchedAt: v.now(), live: true}
	}
	v.lists.Store(&next)
	return errors.Join(errs...)
}

func (v *Verifier) fetch(ctx context.Context, url string) (IPRangeList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return IPRangeList{}, err
	}
	req.Header.Set("User-Agent", "aibouncer/"+Version+" (+https://github.com/emorilebo/aibouncer)")
	req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
	resp, err := v.client.Do(req)
	if err != nil {
		return IPRangeList{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return IPRangeList{}, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, v.maxBodySize+1))
	if err != nil {
		return IPRangeList{}, err
	}
	if int64(len(body)) > v.maxBodySize {
		return IPRangeList{}, fmt.Errorf("response larger than %d bytes", v.maxBodySize)
	}
	return ParseIPRanges(body)
}

// Run refreshes the IP range lists immediately and then every interval until ctx is cancelled.
// Refresh errors are passed to onError if it is non-nil. A typical interval is 12 or 24 hours.
func (v *Verifier) Run(ctx context.Context, interval time.Duration, onError func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := v.Refresh(ctx); err != nil && onError != nil && ctx.Err() == nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// singleflight collapses concurrent reverse-DNS lookups for the same agent and address.
type singleflight struct {
	mu    sync.Mutex
	calls map[dnsCacheKey]*flightCall
}

type flightCall struct {
	done     chan struct{}
	verified bool
	err      error
}

func (s *singleflight) do(key dnsCacheKey, fn func() (bool, error)) (bool, error) {
	s.mu.Lock()
	if s.calls == nil {
		s.calls = make(map[dnsCacheKey]*flightCall)
	}
	if call, ok := s.calls[key]; ok {
		s.mu.Unlock()
		<-call.done
		return call.verified, call.err
	}
	call := &flightCall{done: make(chan struct{})}
	s.calls[key] = call
	s.mu.Unlock()

	call.verified, call.err = fn()
	close(call.done)

	s.mu.Lock()
	delete(s.calls, key)
	s.mu.Unlock()
	return call.verified, call.err
}
