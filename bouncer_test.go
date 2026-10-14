package aibouncer

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emorilebo/aibouncer/webbotauth"
)

func newTestBouncer(t *testing.T, policy Policy) (*Bouncer, *[]Visit) {
	t.Helper()
	srv, _ := newRangeServer(t, testRangesJSON, http.StatusOK)
	catalog := testCatalog(t, srv.URL)
	verifier := NewVerifier(WithVerifierCatalog(catalog), WithHTTPClient(srv.Client()), WithReverseDNS(false))
	if err := verifier.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var visits []Visit
	b := New(WithCatalog(catalog), WithVerifier(verifier), WithPolicy(policy),
		WithOnVisit(func(_ *http.Request, v Visit) {
			mu.Lock()
			defer mu.Unlock()
			visits = append(visits, v)
		}))
	return b, &visits
}

func serve(b *Bouncer, path, userAgent, remote, referer string) (*httptest.ResponseRecorder, Visit) {
	var seen Visit
	handler := b.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = VisitFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("User-Agent", userAgent)
	r.RemoteAddr = remote
	if referer != "" {
		r.Header.Set("Referer", referer)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w, seen
}

func TestMiddlewareDefaultPolicy(t *testing.T) {
	b, visits := newTestBouncer(t, Policy{})

	w, visit := serve(b, "/", "Mozilla/5.0 (compatible; RangeBot/1.0)", "192.0.2.10:4000", "")
	if w.Code != http.StatusOK || visit.Verdict != Verified || visit.Agent.ID != "t-ranges" {
		t.Errorf("genuine bot: code %d, visit %+v", w.Code, visit)
	}

	w, _ = serve(b, "/", "Mozilla/5.0 (compatible; RangeBot/1.0)", "203.0.113.66:4000", "")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "claims to be RangeBot") {
		t.Errorf("impostor: code %d, body %q", w.Code, w.Body.String())
	}

	w, visit = serve(b, "/", "Mozilla/5.0 (Macintosh) Safari/605.1.15", "203.0.113.66:4000", "")
	if w.Code != http.StatusOK || visit.IsAI() || visit.Verdict != NotAI {
		t.Errorf("human: code %d, visit %+v", w.Code, visit)
	}

	w, visit = serve(b, "/post?utm_source=chatgpt.com", "Mozilla/5.0 Safari", "203.0.113.66:4000", "")
	if w.Code != http.StatusOK || visit.Referral == nil || visit.Referral.Assistant != "ChatGPT" {
		t.Errorf("AI referral: code %d, visit %+v", w.Code, visit)
	}

	if len(*visits) != 3 {
		t.Errorf("OnVisit called %d times, want 3 (two bots and one referral, not the plain human)", len(*visits))
	}
}

func TestMiddlewarePurposeAndAgentRules(t *testing.T) {
	b, _ := newTestBouncer(t, Policy{
		Purposes: map[Purpose]Action{PurposeTraining: Block, PurposeSearch: Block},
		Agents:   map[string]Action{"t-cidr": Allow},
	})

	if w, _ := serve(b, "/", "RangeBot/1.0", "192.0.2.10:1", ""); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "does not allow RangeBot (training)") {
		t.Errorf("verified training bot: %d %q", w.Code, w.Body.String())
	}
	if w, _ := serve(b, "/", "CidrBot/1.0", "198.51.100.3:1", ""); w.Code != http.StatusOK {
		t.Errorf("agent override should allow CidrBot, got %d", w.Code)
	}
	if w, _ := serve(b, "/", "TrustMeBot/1.0", "203.0.113.1:1", ""); w.Code != http.StatusOK {
		t.Errorf("unverifiable user agent with no rule should pass, got %d", w.Code)
	}
}

func TestMiddlewareNeverBlocksRobotsTxt(t *testing.T) {
	b, _ := newTestBouncer(t, Policy{Purposes: map[Purpose]Action{PurposeTraining: Block}})
	for _, remote := range []string{"192.0.2.10:1", "203.0.113.66:1"} {
		if w, _ := serve(b, "/robots.txt", "RangeBot/1.0", remote, ""); w.Code != http.StatusOK {
			t.Errorf("robots.txt from %s blocked with %d; a 403 robots.txt means 'allow everything'", remote, w.Code)
		}
	}
}

func TestAllowSpoofedFallsThroughToRules(t *testing.T) {
	b, _ := newTestBouncer(t, Policy{AllowSpoofed: true, Purposes: map[Purpose]Action{PurposeTraining: Block}})
	if w, visit := serve(b, "/", "BothBot/1.0", "203.0.113.66:1", ""); w.Code != http.StatusOK || visit.Verdict != Spoofed {
		t.Errorf("spoofed search bot with AllowSpoofed: %d %+v", w.Code, visit)
	}
	if w, _ := serve(b, "/", "RangeBot/1.0", "203.0.113.66:1", ""); w.Code != http.StatusForbidden {
		t.Errorf("spoofed training bot should still hit the training rule, got %d", w.Code)
	}
}

func TestCustomBlockHandler(t *testing.T) {
	srv, _ := newRangeServer(t, testRangesJSON, http.StatusOK)
	catalog := testCatalog(t, srv.URL)
	v := NewVerifier(WithVerifierCatalog(catalog), WithHTTPClient(srv.Client()), WithReverseDNS(false))
	_ = v.Refresh(context.Background())
	b := New(WithCatalog(catalog), WithVerifier(v), WithBlockHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visit, _ := VisitFromContext(r.Context())
		w.Header().Set("X-Blocked-Agent", visit.Agent.ID)
		w.WriteHeader(http.StatusPaymentRequired)
	})))
	w, _ := serve(b, "/", "RangeBot/1.0", "203.0.113.66:1", "")
	if w.Code != http.StatusPaymentRequired || w.Header().Get("X-Blocked-Agent") != "t-ranges" {
		t.Errorf("custom block handler not used: %d %v", w.Code, w.Header())
	}
}

func TestPolicyRobotsTxt(t *testing.T) {
	catalog := testCatalog(t, "https://unused.invalid/ranges.json")
	got := Policy{Purposes: map[Purpose]Action{PurposeTraining: Block}}.RobotsTxt(catalog)
	for _, want := range []string{"User-agent: RangeBot\n", "User-agent: Test-Extended\n", "Disallow: /\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("robots.txt missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "DnsBot") {
		t.Errorf("search bot should not be disallowed:\n%s", got)
	}
	if got := (Policy{}).RobotsTxt(catalog); !strings.Contains(got, "No AI agents are blocked") {
		t.Errorf("empty policy:\n%s", got)
	}
}

func TestDefaultBouncerWorksOutOfTheBox(t *testing.T) {
	// Pin the max age so the embedded snapshot never counts as stale in CI.
	b := New(WithVerifier(NewVerifier(WithMaxAge(100 * 365 * 24 * time.Hour))))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot")
	r.RemoteAddr = "203.0.113.200:5555" // TEST-NET-3: never in anyone's published ranges
	visit := b.Inspect(r)
	if visit.Agent == nil || visit.Agent.ID != "openai-gptbot" {
		t.Fatalf("visit = %+v", visit)
	}
	if visit.Verdict != Spoofed || visit.Action != Block {
		t.Errorf("GPTBot from a documentation-only IP: verdict %v action %v (%s)", visit.Verdict, visit.Action, visit.Reason)
	}
}

func TestWebBotAuthInMiddleware(t *testing.T) {
	operatorPub, operatorKey, _ := ed25519.GenerateKey(nil)
	_, attackerKey, _ := ed25519.GenerateKey(nil)
	b := New(WithKeySource("openai-chatgpt-agent", webbotauth.NewStaticKeys(operatorPub)))

	signed := func(key ed25519.PrivateKey, agent string) *http.Request {
		r := httptest.NewRequest("GET", "https://shop.example/checkout", nil)
		r.RemoteAddr = "203.0.113.50:443" // not in any IP list: the signature alone must decide
		r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh) Chrome/141.0 Safari/537.36")
		if err := webbotauth.Sign(r, key, webbotauth.SignOptions{SignatureAgent: agent}); err != nil {
			t.Fatal(err)
		}
		return r
	}

	visit := b.Inspect(signed(operatorKey, "https://chatgpt.com"))
	if visit.Agent == nil || visit.Agent.ID != "openai-chatgpt-agent" || visit.Verdict != Verified || visit.Method != "web-bot-auth" {
		t.Errorf("genuine ChatGPT agent: %+v", visit)
	}

	visit = b.Inspect(signed(attackerKey, "https://chatgpt.com"))
	if visit.Agent == nil || visit.Verdict != Spoofed || visit.Action != Block {
		t.Errorf("forged ChatGPT agent signature: %+v", visit)
	}

	tampered := signed(operatorKey, "https://chatgpt.com")
	tampered.Host = "other.example"
	if visit := b.Inspect(tampered); visit.Verdict != Spoofed {
		t.Errorf("signature replayed to another host: %+v", visit)
	}

	// A valid signature from an operator aibouncer does not know is not an AI-agent claim, and
	// its key directory is never fetched.
	if visit := b.Inspect(signed(attackerKey, "https://evil.example")); visit.IsAI() || visit.Action != Allow {
		t.Errorf("unknown signer: %+v", visit)
	}
}

func TestWebBotAuthCanBeDisabled(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	b := New(WithWebBotAuth(false), WithKeySource("openai-chatgpt-agent", webbotauth.NewStaticKeys(pub)))
	r := httptest.NewRequest("GET", "https://shop.example/", nil)
	_ = webbotauth.Sign(r, key, webbotauth.SignOptions{SignatureAgent: "https://chatgpt.com"})
	if visit := b.Inspect(r); visit.IsAI() {
		t.Errorf("with Web Bot Auth disabled a signature-only agent cannot be identified: %+v", visit)
	}
}
