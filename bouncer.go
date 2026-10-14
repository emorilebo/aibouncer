package aibouncer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/emorilebo/aibouncer/webbotauth"
)

// Visit is everything aibouncer learned about a request.
type Visit struct {
	// Agent is the AI agent the request claims to be, or nil.
	Agent *Agent
	// Verdict says whether the claim checked out.
	Verdict Verdict
	// Method is how a verified claim was confirmed.
	Method string
	// Reason explains the verdict in a few words, for logs.
	Reason string
	// ClientIP is the address the verdict was based on.
	ClientIP netip.Addr
	// Referral is set for human visits that clicked through from an AI assistant.
	Referral *Referral
	// Action is what the policy decided.
	Action Action
}

// IsAI reports whether the request claimed to be an AI agent.
func (v Visit) IsAI() bool { return v.Agent != nil }

type visitKey struct{}

// VisitFromContext returns the Visit stored by [Bouncer.Middleware].
func VisitFromContext(ctx context.Context) (Visit, bool) {
	v, ok := ctx.Value(visitKey{}).(Visit)
	return v, ok
}

// Bouncer identifies, verifies and applies policy to AI agents. Create one with [New]; it is
// safe for concurrent use.
type Bouncer struct {
	catalog      *Catalog
	verifier     *Verifier
	policy       Policy
	clientIP     ClientIPFunc
	onVisit      func(*http.Request, Visit)
	blockHandler http.Handler

	webBotAuth bool
	keyClient  *http.Client
	keysMu     sync.Mutex
	keySources map[string]webbotauth.KeySource // by agent ID
}

// Option configures a Bouncer.
type Option func(*Bouncer)

// WithCatalog replaces the embedded catalog.
func WithCatalog(c *Catalog) Option { return func(b *Bouncer) { b.catalog = c } }

// WithVerifier sets the verifier. Run its refresh loop to keep IP data current.
func WithVerifier(v *Verifier) Option { return func(b *Bouncer) { b.verifier = v } }

// WithPolicy sets the policy (default: allow genuine agents, block impostors).
func WithPolicy(p Policy) Option { return func(b *Bouncer) { b.policy = p } }

// WithClientIP sets how the client address is determined (default: [RemoteAddr]). Behind a
// proxy or load balancer use [TrustedProxies].
func WithClientIP(f ClientIPFunc) Option { return func(b *Bouncer) { b.clientIP = f } }

// WithOnVisit registers a callback that runs for every request that claims to be an AI agent
// or arrives from an AI assistant. Use it for logging and metrics; it must not block.
func WithOnVisit(f func(*http.Request, Visit)) Option { return func(b *Bouncer) { b.onVisit = f } }

// WithBlockHandler replaces the default 403 response for blocked requests. The Visit is
// available through [VisitFromContext].
func WithBlockHandler(h http.Handler) Option { return func(b *Bouncer) { b.blockHandler = h } }

// WithWebBotAuth enables or disables Web Bot Auth signature verification (enabled by default).
// When enabled, a signed request from an agent in the catalog is verified against the operator's
// key directory, which is fetched from the URL in the catalog (never from the request) and cached.
func WithWebBotAuth(enabled bool) Option { return func(b *Bouncer) { b.webBotAuth = enabled } }

// WithKeySource pins the Web Bot Auth keys for an agent ID instead of fetching its directory.
func WithKeySource(agentID string, keys webbotauth.KeySource) Option {
	return func(b *Bouncer) { b.keySources[agentID] = keys }
}

// New returns a Bouncer. Without options it uses the embedded catalog, a Verifier initialised
// from the embedded IP snapshot, the zero Policy, and the TCP peer address.
func New(opts ...Option) *Bouncer {
	b := &Bouncer{
		policy:       Policy{},
		clientIP:     RemoteAddr,
		blockHandler: http.HandlerFunc(defaultBlockHandler),
		webBotAuth:   true,
		keyClient:    &http.Client{Timeout: 10 * time.Second},
		keySources:   map[string]webbotauth.KeySource{},
	}
	for _, opt := range opts {
		opt(b)
	}
	if b.catalog == nil {
		b.catalog = DefaultCatalog()
	}
	if b.verifier == nil {
		b.verifier = NewVerifier(WithVerifierCatalog(b.catalog))
	}
	return b
}

// Verifier returns the bouncer's verifier, e.g. to run its refresh loop.
func (b *Bouncer) Verifier() *Verifier { return b.verifier }

// Inspect identifies and verifies the request and applies the policy, without serving it.
func (b *Bouncer) Inspect(r *http.Request) Visit {
	visit := Visit{Verdict: NotAI, Action: Allow}
	if addr, ok := b.clientIP(r); ok {
		visit.ClientIP = addr
	}

	uaAgent, _ := b.catalog.Identify(r.UserAgent())
	if b.webBotAuth && webbotauth.Signed(r) {
		if agent, result, ok := b.verifySignature(r, uaAgent); ok {
			visit.Agent, visit.Verdict, visit.Method, visit.Reason = agent, result.Verdict, result.Method, result.Reason
			visit.Action = b.policy.Decide(agent, result.Verdict)
			return visit
		}
	}
	if uaAgent != nil {
		result := b.verifier.VerifyIP(r.Context(), uaAgent, visit.ClientIP)
		visit.Agent, visit.Verdict, visit.Method, visit.Reason = uaAgent, result.Verdict, result.Method, result.Reason
		visit.Action = b.policy.Decide(uaAgent, result.Verdict)
		return visit
	}

	if referral, ok := b.catalog.DetectReferral(r); ok {
		visit.Referral = &referral
	}
	return visit
}

// verifySignature checks a Web Bot Auth signature. The signer is the catalog agent whose
// documented Signature-Agent matches the request's, or else the agent named by the User-Agent.
// It reports ok=false when the signature cannot be attributed to a known agent or the key
// directory is unreachable, so the caller falls back to IP verification.
func (b *Bouncer) verifySignature(r *http.Request, uaAgent *Agent) (*Agent, Result, bool) {
	agent := b.agentForSignatureAgents(webbotauth.SignatureAgents(r.Header))
	if agent == nil && uaAgent != nil && uaAgent.WebBotAuth != nil {
		agent = uaAgent
	}
	if agent == nil {
		return nil, Result{}, false
	}
	keys := b.keySource(agent)
	if keys == nil {
		return nil, Result{}, false
	}

	result := Result{Agent: agent}
	verified, err := webbotauth.Verify(r.Context(), r, keys, webbotauth.Options{})
	switch {
	case err == nil:
		if expected := signatureAgentOrigin(agent); expected != "" && verified.SignatureAgent != "" && !sameOrigin(verified.SignatureAgent, expected) {
			result.Verdict, result.Reason = Spoofed, "signed Signature-Agent does not match "+agent.Name
			return agent, result, true
		}
		result.Verdict, result.Method = Verified, "web-bot-auth"
		result.Reason = "valid Web Bot Auth signature from " + agent.Operator + "'s key directory"
		return agent, result, true
	case errors.Is(err, webbotauth.ErrInvalidSignature), errors.Is(err, webbotauth.ErrUnknownKey):
		result.Verdict, result.Reason = Spoofed, "Web Bot Auth signature failed: "+err.Error()
		return agent, result, true
	default:
		return nil, Result{}, false // key directory unreachable: inconclusive, fall back
	}
}

func (b *Bouncer) agentForSignatureAgents(agents []string) *Agent {
	for _, claimed := range agents {
		for i := range b.catalog.Agents {
			agent := &b.catalog.Agents[i]
			if expected := signatureAgentOrigin(agent); expected != "" && sameOrigin(claimed, expected) {
				return agent
			}
		}
	}
	return nil
}

func (b *Bouncer) keySource(agent *Agent) webbotauth.KeySource {
	b.keysMu.Lock()
	defer b.keysMu.Unlock()
	if keys, ok := b.keySources[agent.ID]; ok {
		return keys
	}
	if agent.WebBotAuth == nil || agent.WebBotAuth.KeyDirectory == "" {
		return nil
	}
	dir := webbotauth.NewDirectory(agent.WebBotAuth.KeyDirectory, b.keyClient)
	b.keySources[agent.ID] = dir
	return dir
}

// signatureAgentOrigin returns the URL from the agent's documented Signature-Agent header value,
// which the catalog stores verbatim (e.g. "\"https://chatgpt.com\"" or "g=\"https://agent.bot.goog\"").
func signatureAgentOrigin(agent *Agent) string {
	if agent.WebBotAuth == nil || agent.WebBotAuth.SignatureAgent == "" {
		return ""
	}
	agents := webbotauth.SignatureAgents(http.Header{"Signature-Agent": {agent.WebBotAuth.SignatureAgent}})
	if len(agents) == 0 {
		return ""
	}
	return agents[0]
}

func sameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil || ua.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// Middleware wraps next. Blocked requests get the block handler; every other request reaches
// next with the Visit available through [VisitFromContext].
//
// Requests for /robots.txt are never blocked: RFC 9309 treats a 4xx robots.txt as "no rules",
// so blocking it would tell well-behaved crawlers they may fetch everything.
func (b *Bouncer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visit := b.Inspect(r)
		if r.URL.Path == "/robots.txt" {
			visit.Action = Allow
		}
		if b.onVisit != nil && (visit.Agent != nil || visit.Referral != nil) {
			b.onVisit(r, visit)
		}
		r = r.WithContext(context.WithValue(r.Context(), visitKey{}, visit))
		if visit.Action == Block {
			b.blockHandler.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func defaultBlockHandler(w http.ResponseWriter, r *http.Request) {
	visit, _ := VisitFromContext(r.Context())
	message := "Forbidden"
	if visit.Agent != nil {
		if visit.Verdict == Spoofed {
			message = fmt.Sprintf("Forbidden: this request claims to be %s but does not come from %s's published network", visit.Agent.Name, visit.Agent.Operator)
		} else {
			message = fmt.Sprintf("Forbidden: this site does not allow %s (%s)", visit.Agent.Name, visit.Agent.Purpose)
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintln(w, message)
}
