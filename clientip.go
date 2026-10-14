package aibouncer

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIPFunc extracts the address of the client that sent a request.
// It returns false if no usable address is available.
type ClientIPFunc func(r *http.Request) (netip.Addr, bool)

// RemoteAddr returns the address of the TCP peer (r.RemoteAddr). It is the default because it
// cannot be forged by the client. Use [TrustedProxies] when the server sits behind a proxy or
// load balancer.
func RemoteAddr(r *http.Request) (netip.Addr, bool) {
	return parseHostPort(r.RemoteAddr)
}

// TrustedProxies returns a ClientIPFunc for servers behind reverse proxies or load balancers.
//
// It reads the X-Forwarded-For header from right to left and returns the first address that is
// not inside one of the trusted prefixes; that is the last hop no trusted proxy can vouch for.
// Headers are only consulted when the TCP peer itself is trusted, so a client talking to the
// server directly cannot inject a forwarded address. Pick the prefixes of your own proxies,
// e.g. netip.MustParsePrefix("10.0.0.0/8"); never trust 0.0.0.0/0.
func TrustedProxies(trusted ...netip.Prefix) ClientIPFunc {
	isTrusted := func(addr netip.Addr) bool {
		for _, prefix := range trusted {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}

	return func(r *http.Request) (netip.Addr, bool) {
		peer, ok := parseHostPort(r.RemoteAddr)
		if !ok || !isTrusted(peer) {
			return peer, ok
		}
		hops := r.Header.Values("X-Forwarded-For")
		for i := len(hops) - 1; i >= 0; i-- {
			parts := strings.Split(hops[i], ",")
			for j := len(parts) - 1; j >= 0; j-- {
				addr, ok := parseForwarded(parts[j])
				if !ok {
					return netip.Addr{}, false // a malformed hop makes the chain untrustworthy
				}
				if !isTrusted(addr) {
					return addr, true
				}
			}
		}
		return peer, true // every hop is trusted, so the request originated inside the trusted network
	}
}

func parseHostPort(hostPort string) (netip.Addr, bool) {
	if addrPort, err := netip.ParseAddrPort(hostPort); err == nil {
		return addrPort.Addr().Unmap(), true
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// parseForwarded accepts "1.2.3.4", "1.2.3.4:5678", "2001:db8::1", "[2001:db8::1]" and
// "[2001:db8::1]:443", the forms proxies use in X-Forwarded-For.
func parseForwarded(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if addr, ok := parseHostPort(value); ok {
		return addr, true
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		if addr, err := netip.ParseAddr(value[1 : len(value)-1]); err == nil {
			return addr.Unmap(), true
		}
	}
	return netip.Addr{}, false
}
