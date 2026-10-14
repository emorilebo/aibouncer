package aibouncer

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestParseIPRangesGoogleShape(t *testing.T) {
	data := []byte(`{
  "creationTime": "2026-10-01T15:46:04.000000",
  "prefixes": [
    {"ipv4Prefix": "192.0.2.0/27"},
    {"ipv4Prefix": "192.0.2.5/27"},
    {"ipv6Prefix": "2001:db8:4801:7428::/64"},
    {"ipv4Prefix": "192.0.2.0/27"}
  ]
}`)
	list, err := ParseIPRanges(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Prefixes) != 2 {
		t.Fatalf("got %v, want 2 de-duplicated, masked prefixes", list.Prefixes)
	}
	if want := time.Date(2026, 10, 1, 15, 46, 4, 0, time.UTC); !list.CreationTime.Equal(want) {
		t.Errorf("CreationTime = %v, want %v", list.CreationTime, want)
	}
	set := newPrefixSet(list.Prefixes)
	for addr, want := range map[string]bool{
		"192.0.2.31":            true,
		"192.0.2.32":            false,
		"2001:db8:4801:7428::9": true,
		"2001:db8:4801:7429::9": false,
		"::ffff:192.0.2.1":      true,
	} {
		if got := set.contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("contains(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestParseIPRangesUnknownJSONShape(t *testing.T) {
	data := []byte(`{"updated":"yesterday","ranges":{"v4":["198.51.100.0/24"],"single":"203.0.113.9"},"note":"10/10 would crawl again"}`)
	list, err := ParseIPRanges(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.9/32")}
	if len(list.Prefixes) != len(want) || list.Prefixes[0] != want[0] || list.Prefixes[1] != want[1] {
		t.Errorf("got %v, want %v", list.Prefixes, want)
	}
}

func TestParseIPRangesPlainText(t *testing.T) {
	data := []byte("# crawler IPs\n198.51.100.0/24\n\n2001:db8::/32 # v6\nnot a prefix\n")
	list, err := ParseIPRanges(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Prefixes) != 2 {
		t.Errorf("got %v", list.Prefixes)
	}
}

func TestParseIPRangesEmbeddedInHTML(t *testing.T) {
	// Amazon publishes its crawler IPs inside HTML pages, with inconsistent key names and with
	// or without a prefix length. Version strings elsewhere on the page must not be picked up.
	data := []byte(`<html><head><script src="/lib-1.2.3.4.js"></script></head><body>
<pre>{"prefixes": [{"ipv4Prefix": "192.0.2.10"}, {"ip_prefix": "198.51.100.0/24"}]}</pre>
<div data-x="{&quot;ipv6Prefix&quot;:&quot;2001:db8::/32&quot;}">jQuery 3.6.0.1</div></body></html>`)
	list, err := ParseIPRanges(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[netip.Prefix]bool{
		netip.MustParsePrefix("192.0.2.10/32"):   true,
		netip.MustParsePrefix("198.51.100.0/24"): true,
		netip.MustParsePrefix("2001:db8::/32"):   true,
	}
	if len(list.Prefixes) != len(want) {
		t.Fatalf("got %v", list.Prefixes)
	}
	for _, p := range list.Prefixes {
		if !want[p] {
			t.Errorf("unexpected prefix %v", p)
		}
	}
}

func TestParseIPRangesErrors(t *testing.T) {
	if _, err := ParseIPRanges([]byte(`{"prefixes": []}`)); !errors.Is(err, ErrNoPrefixes) {
		t.Errorf("empty list: err = %v", err)
	}
	if _, err := ParseIPRanges([]byte(`{"prefixes": [`)); err == nil {
		t.Error("truncated JSON must fail")
	}
	if _, err := ParseIPRanges([]byte(`<html>404</html>`)); !errors.Is(err, ErrNoPrefixes) {
		t.Errorf("HTML error page: err = %v", err)
	}
}

func BenchmarkPrefixSetContains(b *testing.B) {
	var prefixes []netip.Prefix
	for i := 0; i < 1024; i++ {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{100, byte(i >> 8), byte(i), 0}), 24))
	}
	set := newPrefixSet(prefixes)
	miss := netip.MustParseAddr("203.0.113.1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = set.contains(miss)
	}
}
