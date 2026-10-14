package aibouncer

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestRemoteAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:51234":          "203.0.113.7",
		"[2001:db8::1]:443":          "2001:db8::1",
		"[::ffff:203.0.113.7]:51234": "203.0.113.7", // IPv4-mapped addresses are unmapped
		"203.0.113.7":                "203.0.113.7",
	}
	for remote, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		got, ok := RemoteAddr(r)
		if !ok || got != netip.MustParseAddr(want) {
			t.Errorf("RemoteAddr(%q) = %v, %v; want %s", remote, got, ok, want)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "pipe"
	if _, ok := RemoteAddr(r); ok {
		t.Error("non-IP RemoteAddr must not parse")
	}
}

func TestTrustedProxies(t *testing.T) {
	clientIP := TrustedProxies(netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:ffff::/48"))

	cases := []struct {
		name   string
		remote string
		xff    []string
		want   string
		ok     bool
	}{
		{"direct client cannot spoof XFF", "198.51.100.9:1234", []string{"20.15.240.64"}, "198.51.100.9", true},
		{"single trusted proxy", "10.0.0.2:80", []string{"20.15.240.64"}, "20.15.240.64", true},
		{"rightmost untrusted hop wins", "10.0.0.2:80", []string{"6.6.6.6, 20.15.240.64, 10.0.0.9"}, "20.15.240.64", true},
		{"multiple headers are concatenated", "10.0.0.2:80", []string{"6.6.6.6", "20.15.240.64"}, "20.15.240.64", true},
		{"bracketed IPv6 with port", "10.0.0.2:80", []string{"[2001:db8::7]:443"}, "2001:db8::7", true},
		{"no header falls back to peer", "10.0.0.2:80", nil, "10.0.0.2", true},
		{"all hops trusted", "10.0.0.2:80", []string{"10.1.1.1"}, "10.0.0.2", true},
		{"garbage hop is rejected", "10.0.0.2:80", []string{"not-an-ip"}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remote
			for _, v := range c.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			got, ok := clientIP(r)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if c.ok && got != netip.MustParseAddr(c.want) {
				t.Errorf("got %v, want %s", got, c.want)
			}
		})
	}
}
