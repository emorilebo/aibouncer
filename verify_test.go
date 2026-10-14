package aibouncer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeResolver answers PTR and A/AAAA lookups from maps and counts calls.
type fakeResolver struct {
	ptr     map[string][]string
	forward map[string][]netip.Addr
	err     error
	calls   atomic.Int32
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	names, ok := f.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return names, nil
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	addrs, ok := f.forward[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

const testRangesJSON = `{"creationTime":"2026-10-01T00:00:00.000000","prefixes":[{"ipv4Prefix":"192.0.2.0/24"},{"ipv6Prefix":"2001:db8:aa::/48"}]}`

func testCatalog(t *testing.T, rangesURL string) *Catalog {
	t.Helper()
	c, err := LoadCatalog([]byte(fmt.Sprintf(`{"generated":"test","agents":[
	  {"id":"t-ranges","name":"RangeBot","operator":"Test","purpose":"training","user_agent_tokens":["RangeBot"],"robots_token":"RangeBot","robots_txt":"honors","ip_ranges":[%q],"docs":"https://example.com"},
	  {"id":"t-dns","name":"DnsBot","operator":"Test","purpose":"search","user_agent_tokens":["DnsBot"],"robots_token":"DnsBot","robots_txt":"honors","reverse_dns":["crawl.example.net"],"docs":"https://example.com"},
	  {"id":"t-both","name":"BothBot","operator":"Test","purpose":"search","user_agent_tokens":["BothBot"],"robots_token":"BothBot","robots_txt":"honors","ip_ranges":[%q],"reverse_dns":["crawl.example.net"],"docs":"https://example.com"},
	  {"id":"t-cidr","name":"CidrBot","operator":"Test","purpose":"search","user_agent_tokens":["CidrBot"],"robots_txt":"honors","cidrs":["198.51.100.0/24"],"docs":"https://example.com"},
	  {"id":"t-shared","name":"SharedBot","operator":"Test","purpose":"user","user_agent_tokens":["SharedBot"],"robots_txt":"unspecified","shared_ip_ranges":[%q],"reverse_dns":["crawl.example.net"],"docs":"https://example.com"},
	  {"id":"t-none","name":"TrustMeBot","operator":"Test","purpose":"user","user_agent_tokens":["TrustMeBot"],"robots_txt":"unspecified","docs":"https://example.com"},
	  {"id":"t-extended","name":"Test-Extended","operator":"Test","purpose":"training","robots_token":"Test-Extended","robots_only":true,"robots_txt":"control_token_only","docs":"https://example.com"}
	],"referrals":[{"assistant":"ChatGPT","hosts":["chatgpt.com"],"utm_sources":["chatgpt.com"],"evidence":"official"}]}`, rangesURL, rangesURL, rangesURL)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newRangeServer(t *testing.T, body string, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.HasPrefix(r.UserAgent(), "aibouncer/") {
			t.Errorf("refresh sent User-Agent %q", r.UserAgent())
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestVerifyIPRanges(t *testing.T) {
	srv, _ := newRangeServer(t, testRangesJSON, http.StatusOK)
	catalog := testCatalog(t, srv.URL)
	v := NewVerifier(WithVerifierCatalog(catalog), WithHTTPClient(srv.Client()), WithReverseDNS(false))
	agent, _ := catalog.Agent("t-ranges")

	before := v.VerifyIP(context.Background(), agent, netip.MustParseAddr("192.0.2.10"))
	if before.Verdict != Unverifiable {
		t.Fatalf("before refresh: %v (%s), want unverifiable", before.Verdict, before.Reason)
	}
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Verdict{
		"192.0.2.10":        Verified,
		"::ffff:192.0.2.10": Verified,
		"2001:db8:aa::1":    Verified,
		"203.0.113.66":      Spoofed,
		"2001:db8:bb::1":    Spoofed,
	}
	for addr, want := range cases {
		got := v.VerifyIP(context.Background(), agent, netip.MustParseAddr(addr))
		if got.Verdict != want {
			t.Errorf("VerifyIP(%s) = %v (%s), want %v", addr, got.Verdict, got.Reason, want)
		}
	}
	var found bool
	for _, st := range v.Status() {
		if st.URL == srv.URL {
			found = true
			if st.Prefixes != 2 || !st.Live || st.LastError != nil {
				t.Errorf("Status() for test server = %+v", st)
			}
		}
	}
	if !found {
		t.Error("Status() does not list the refreshed source")
	}
}

func TestStaleDataFailsOpen(t *testing.T) {
	srv, _ := newRangeServer(t, testRangesJSON, http.StatusOK)
	catalog := testCatalog(t, srv.URL)
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	v := NewVerifier(WithVerifierCatalog(catalog), WithHTTPClient(srv.Client()), WithReverseDNS(false),
		WithClock(func() time.Time { return now }), WithMaxAge(24*time.Hour))
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	agent, _ := catalog.Agent("t-ranges")
	now = now.Add(48 * time.Hour)

	if got := v.VerifyIP(context.Background(), agent, netip.MustParseAddr("203.0.113.66")); got.Verdict != Unverifiable {
		t.Errorf("miss on stale data = %v, want unverifiable", got.Verdict)
	}
	if got := v.VerifyIP(context.Background(), agent, netip.MustParseAddr("192.0.2.10")); got.Verdict != Verified {
		t.Errorf("hit on stale data = %v, want verified", got.Verdict)
	}
}

func TestRefreshFailureKeepsPreviousData(t *testing.T) {
	body := testRangesJSON
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	catalog := testCatalog(t, srv.URL)
	v := NewVerifier(WithVerifierCatalog(catalog), WithHTTPClient(srv.Client()), WithReverseDNS(false))
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	status, body = http.StatusServiceUnavailable, "maintenance"
	if err := v.Refresh(context.Background()); err == nil {
		t.Fatal("expected an error from a 503")
	}
	status, body = http.StatusOK, "<html>oops</html>"
	if err := v.Refresh(context.Background()); !errors.Is(err, ErrNoPrefixes) {
		t.Fatalf("err = %v, want ErrNoPrefixes", err)
	}

	agent, _ := catalog.Agent("t-ranges")
	if got := v.VerifyIP(context.Background(), agent, netip.MustParseAddr("192.0.2.10")); got.Verdict != Verified {
		t.Errorf("after failed refreshes: %v, want the old data to still verify", got.Verdict)
	}
	for _, st := range v.Status() {
		if st.URL == srv.URL && st.LastError == nil {
			t.Error("Status should report the last refresh error")
		}
	}
}

func TestReverseDNSVerification(t *testing.T) {
	resolver := &fakeResolver{
		ptr: map[string][]string{
			"203.0.113.5": {"bot-203-0-113-5.crawl.example.net."},
			"203.0.113.6": {"bot.crawl.example.net.evil.test."}, // suffix trick
			"203.0.113.7": {"bot-7.crawl.example.net."},         // PTR claims it, forward DNS disagrees
			"203.0.113.8": {"notcrawl.example.net."},
		},
		forward: map[string][]netip.Addr{
			"bot-203-0-113-5.crawl.example.net": {netip.MustParseAddr("203.0.113.5")},
			"bot-7.crawl.example.net":           {netip.MustParseAddr("198.51.100.1")},
		},
	}
	catalog := testCatalog(t, "https://unused.invalid/ranges.json")
	v := NewVerifier(WithVerifierCatalog(catalog), WithResolver(resolver))
	agent, _ := catalog.Agent("t-dns")

	cases := map[string]Verdict{
		"203.0.113.5": Verified,
		"203.0.113.6": Spoofed,
		"203.0.113.7": Spoofed,
		"203.0.113.8": Spoofed,
		"203.0.113.9": Spoofed, // no PTR at all
	}
	for addr, want := range cases {
		if got := v.VerifyIP(context.Background(), agent, netip.MustParseAddr(addr)); got.Verdict != want {
			t.Errorf("VerifyIP(%s) = %v (%s), want %v", addr, got.Verdict, got.Reason, want)
		}
	}

	calls := resolver.calls.Load()
	v.VerifyIP(context.Background(), agent, netip.MustParseAddr("203.0.113.5"))
	if resolver.calls.Load() != calls {
		t.Error("second lookup for the same IP should be served from the cache")
	}
}

func TestReverseDNSErrorIsUnverifiable(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("i/o timeout")}
	catalog := testCatalog(t, "https://unused.invalid/ranges.json")
	v := NewVerifier(WithVerifierCatalog(catalog), WithResolver(resolver))
	agent, _ := catalog.Agent("t-dns")
	if got := v.VerifyIP(context.Background(), agent, netip.MustParseAddr("203.0.113.5")); got.Verdict != Unverifiable {
		t.Errorf("DNS failure = %v, want unverifiable", got.Verdict)
	}
}

func TestRangesMissFallsBackToReverseDNS(t *testing.T) {
	srv, _ := newRangeServer(t, testRangesJSON, http.StatusOK)
	resolver := &fakeResolver{
		ptr:     map[string][]string{"203.0.113.5": {"b.crawl.example.net"}},
		forward: map[string][]netip.Addr{"b.crawl.example.net": {netip.MustParseAddr("203.0.113.5")}},
	}
	catalog := testCatalog(t, srv.URL)
	v := NewVerifier(WithVerifierCatalog(catalog), WithHTTPClient(srv.Client()), WithResolver(resolver))
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	agent, _ := catalog.Agent("t-both")
	got := v.VerifyIP(context.Background(), agent, netip.MustParseAddr("203.0.113.5"))
	if got.Verdict != Verified || got.Method != "reverse-dns" {
		t.Errorf("got %v via %q, want verified via reverse-dns (published lists can lag)", got.Verdict, got.Method)
	}
}

func TestSharedRangesArePlausibleNotProof(t *testing.T) {
	srv, _ := newRangeServer(t, testRangesJSON, http.StatusOK)
	resolver := &fakeResolver{
		ptr:     map[string][]string{"192.0.2.77": {"b.crawl.example.net"}},
		forward: map[string][]netip.Addr{"b.crawl.example.net": {netip.MustParseAddr("192.0.2.77")}},
	}
	catalog := testCatalog(t, srv.URL)
	v := NewVerifier(WithVerifierCatalog(catalog), WithHTTPClient(srv.Client()), WithResolver(resolver))
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	agent, _ := catalog.Agent("t-shared")
	cases := map[string]Verdict{
		"192.0.2.10":   Unverifiable, // in the shared list, reverse DNS does not confirm
		"192.0.2.77":   Verified,     // in the shared list and confirmed by reverse DNS
		"203.0.113.66": Spoofed,      // in no list and no reverse DNS
	}
	for addr, want := range cases {
		if got := v.VerifyIP(context.Background(), agent, netip.MustParseAddr(addr)); got.Verdict != want {
			t.Errorf("VerifyIP(%s) = %v (%s), want %v", addr, got.Verdict, got.Reason, want)
		}
	}
	noDNS := NewVerifier(WithVerifierCatalog(catalog), WithHTTPClient(srv.Client()), WithReverseDNS(false))
	_ = noDNS.Refresh(context.Background())
	if got := noDNS.VerifyIP(context.Background(), agent, netip.MustParseAddr("192.0.2.10")); got.Verdict != Unverifiable {
		t.Errorf("shared hit without DNS = %v, want unverifiable", got.Verdict)
	}
}

func TestDocumentedCIDRAndUnverifiableAgents(t *testing.T) {
	catalog := testCatalog(t, "https://unused.invalid/ranges.json")
	v := NewVerifier(WithVerifierCatalog(catalog), WithReverseDNS(false))
	cidr, _ := catalog.Agent("t-cidr")
	if got := v.VerifyIP(context.Background(), cidr, netip.MustParseAddr("198.51.100.20")); got.Verdict != Verified || got.Method != "documented-cidr" {
		t.Errorf("documented CIDR hit = %v via %q", got.Verdict, got.Method)
	}
	if got := v.VerifyIP(context.Background(), cidr, netip.MustParseAddr("203.0.113.1")); got.Verdict != Spoofed {
		t.Errorf("documented CIDR miss = %v, want spoofed", got.Verdict)
	}
	none, _ := catalog.Agent("t-none")
	if got := v.VerifyIP(context.Background(), none, netip.MustParseAddr("203.0.113.1")); got.Verdict != Unverifiable {
		t.Errorf("agent without verification = %v, want unverifiable", got.Verdict)
	}
	if got := v.VerifyIP(context.Background(), none, netip.Addr{}); got.Verdict != Unverifiable {
		t.Errorf("unknown client IP = %v, want unverifiable", got.Verdict)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	srv, _ := newRangeServer(t, testRangesJSON, http.StatusOK)
	catalog := testCatalog(t, srv.URL)
	v := NewVerifier(WithVerifierCatalog(catalog), WithHTTPClient(srv.Client()), WithReverseDNS(false))
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored := NewVerifier(WithVerifierCatalog(catalog), WithSnapshot(v.Snapshot()), WithReverseDNS(false))
	agent, _ := catalog.Agent("t-ranges")
	if got := restored.VerifyIP(context.Background(), agent, netip.MustParseAddr("2001:db8:aa::9")); got.Verdict != Verified {
		t.Errorf("restored snapshot = %v, want verified", got.Verdict)
	}
}

func TestDNSCacheIsBounded(t *testing.T) {
	cache := newDNSCache(3)
	now := time.Now()
	for i := 0; i < 50; i++ {
		cache.put(dnsCacheKey{agentID: "a", addr: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, true, now.Add(time.Hour), now)
	}
	if len(cache.entries) > 3 {
		t.Errorf("cache grew to %d entries", len(cache.entries))
	}
}

func TestEmbeddedSnapshotCoversCatalog(t *testing.T) {
	v := NewVerifier()
	have := map[string]int{}
	for _, s := range v.Status() {
		have[s.URL] = s.Prefixes
	}
	for _, agent := range DefaultCatalog().Agents {
		for _, url := range append(append([]string{}, agent.IPRanges...), agent.SharedIPRanges...) {
			if have[url] == 0 {
				t.Errorf("embedded snapshot has no prefixes for %s (%s)", url, agent.ID)
			}
		}
	}
}
