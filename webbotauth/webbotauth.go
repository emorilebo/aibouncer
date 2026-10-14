// Package webbotauth verifies and creates Web Bot Auth signatures: HTTP Message Signatures
// (RFC 9421) that AI agents and crawlers attach to their requests so websites can confirm who
// sent them, following draft-meunier-web-bot-auth-architecture.
//
// Verification checks that the request carries a signature tagged "web-bot-auth", that it covers
// @authority (or @target-uri) and, when present, the Signature-Agent header, that it is within
// its created/expires window, and that the Ed25519 signature is valid for a key whose RFC 8037
// thumbprint equals the keyid. Keys come from a [KeySource], typically a [Directory] pointing at
// an operator's /.well-known/http-message-signatures-directory.
//
// Only Ed25519 is supported, which is what the operators that publish key directories use.
package webbotauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Tag is the signature tag that identifies Web Bot Auth signatures.
const Tag = "web-bot-auth"

var (
	// ErrNoSignature means the request carries no Web Bot Auth signature.
	ErrNoSignature = errors.New("webbotauth: request is not signed")
	// ErrInvalidSignature means a signature was present but did not verify.
	ErrInvalidSignature = errors.New("webbotauth: invalid signature")
	// ErrUnknownKey means the keyid is not in the key source.
	ErrUnknownKey = errors.New("webbotauth: unknown key")
)

// Key is an Ed25519 public key from a key directory.
type Key struct {
	ID        string
	PublicKey ed25519.PublicKey
	NotBefore time.Time // zero if unbounded
	Expires   time.Time // zero if unbounded
}

// KeySource looks up keys by keyid. It returns an error wrapping ErrUnknownKey if the key does
// not exist and any other error if the lookup itself failed.
type KeySource interface {
	Key(ctx context.Context, keyID string) (Key, error)
}

// Thumbprint returns the RFC 8037 / RFC 7638 JWK SHA-256 thumbprint of an Ed25519 public key,
// base64url-encoded without padding. Web Bot Auth uses it as the keyid.
func Thumbprint(pub ed25519.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub)
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Result describes a verified signature.
type Result struct {
	Label   string
	KeyID   string
	Created time.Time
	Expires time.Time
	// SignatureAgent is the signed Signature-Agent value, if the signature covered it.
	SignatureAgent string
}

// Options tunes verification.
type Options struct {
	// Now returns the current time (default time.Now).
	Now func() time.Time
	// Skew is the tolerated clock difference for created and expires (default 1 minute).
	Skew time.Duration
	// MaxValidity, if set, rejects signatures whose expires-created window is longer. The draft
	// recommends at most 24 hours but does not require it, so the default is no limit.
	MaxValidity time.Duration
}

func (o Options) withDefaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Skew == 0 {
		o.Skew = time.Minute
	}
	return o
}

// Signed reports whether the request carries a Signature-Input header with a web-bot-auth tag,
// without verifying anything.
func Signed(r *http.Request) bool {
	members, err := parseDictionary(strings.Join(r.Header.Values("Signature-Input"), ", "))
	if err != nil {
		return false
	}
	for _, m := range members {
		if m.innerList == nil {
			continue
		}
		if tag, ok := findParam(m.innerList.params, "tag"); ok && tag.kind == sfString && tag.text == Tag {
			return true
		}
	}
	return false
}

// SignatureAgents returns the URLs in the Signature-Agent header. It accepts both the current
// dictionary form (sig1="https://agent.example") and the legacy string form ("https://agent.example").
func SignatureAgents(h http.Header) []string {
	raw := strings.Join(h.Values("Signature-Agent"), ", ")
	if raw == "" {
		return nil
	}
	if item, err := parseItem(raw); err == nil && item.value.kind == sfString {
		return []string{item.value.text}
	}
	members, err := parseDictionary(raw)
	if err != nil {
		return nil
	}
	var agents []string
	for _, m := range members {
		if m.item != nil && m.item.value.kind == sfString {
			agents = append(agents, m.item.value.text)
		}
	}
	return agents
}

// Verify checks the request's Web Bot Auth signatures and returns the first one that verifies.
// It returns ErrNoSignature if there is none, and an error wrapping ErrInvalidSignature or
// ErrUnknownKey if signatures exist but none verifies.
func Verify(ctx context.Context, r *http.Request, keys KeySource, opts Options) (Result, error) {
	opts = opts.withDefaults()
	inputs, err := parseDictionary(strings.Join(r.Header.Values("Signature-Input"), ", "))
	if err != nil {
		return Result{}, fmt.Errorf("%w: Signature-Input: %v", ErrInvalidSignature, err)
	}
	signatures, err := parseDictionary(strings.Join(r.Header.Values("Signature"), ", "))
	if err != nil {
		return Result{}, fmt.Errorf("%w: Signature: %v", ErrInvalidSignature, err)
	}

	var firstErr error
	found := false
	for _, input := range inputs {
		if input.innerList == nil {
			continue
		}
		if tag, ok := findParam(input.innerList.params, "tag"); !ok || tag.kind != sfString || tag.text != Tag {
			continue
		}
		found = true
		result, err := verifyOne(ctx, r, input, signatures, keys, opts)
		if err == nil {
			return result, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if !found {
		return Result{}, ErrNoSignature
	}
	return Result{}, firstErr
}

func verifyOne(ctx context.Context, r *http.Request, input sfMember, signatures []sfMember, keys KeySource, opts Options) (Result, error) {
	result := Result{Label: input.key}
	params := input.innerList.params

	var signature []byte
	for _, s := range signatures {
		if s.key == input.key && s.item != nil && s.item.value.kind == sfBytes {
			signature = s.item.value.bytes
		}
	}
	if signature == nil {
		return result, fmt.Errorf("%w: no Signature for label %q", ErrInvalidSignature, input.key)
	}

	keyID, ok := findParam(params, "keyid")
	if !ok || keyID.kind != sfString {
		return result, fmt.Errorf("%w: keyid missing", ErrInvalidSignature)
	}
	result.KeyID = keyID.text
	if alg, ok := findParam(params, "alg"); ok && (alg.kind != sfString || alg.text != "ed25519") {
		return result, fmt.Errorf("%w: unsupported alg", ErrInvalidSignature)
	}

	created, ok := findParam(params, "created")
	if !ok || created.kind != sfInteger {
		return result, fmt.Errorf("%w: created missing", ErrInvalidSignature)
	}
	expires, ok := findParam(params, "expires")
	if !ok || expires.kind != sfInteger {
		return result, fmt.Errorf("%w: expires missing", ErrInvalidSignature)
	}
	result.Created, result.Expires = time.Unix(created.integer, 0), time.Unix(expires.integer, 0)
	now := opts.Now()
	switch {
	case result.Created.After(now.Add(opts.Skew)):
		return result, fmt.Errorf("%w: created is in the future", ErrInvalidSignature)
	case now.After(result.Expires.Add(opts.Skew)):
		return result, fmt.Errorf("%w: signature expired", ErrInvalidSignature)
	case opts.MaxValidity > 0 && result.Expires.Sub(result.Created) > opts.MaxValidity:
		return result, fmt.Errorf("%w: validity window longer than %s", ErrInvalidSignature, opts.MaxValidity)
	}

	coversTarget := false
	for _, component := range input.innerList.items {
		if component.value.kind != sfString {
			return result, fmt.Errorf("%w: component is not a string", ErrInvalidSignature)
		}
		switch component.value.text {
		case "@authority", "@target-uri":
			coversTarget = true
		case "signature-agent":
			value, err := componentValue(r, component)
			if err != nil {
				return result, err
			}
			result.SignatureAgent = unquoteSF(value)
		}
	}
	if !coversTarget {
		return result, fmt.Errorf("%w: signature must cover @authority or @target-uri", ErrInvalidSignature)
	}
	if len(r.Header.Values("Signature-Agent")) > 0 && result.SignatureAgent == "" {
		return result, fmt.Errorf("%w: Signature-Agent header is not covered by the signature", ErrInvalidSignature)
	}

	base, err := signatureBase(r, *input.innerList, false)
	if err != nil {
		return result, err
	}
	key, err := keys.Key(ctx, keyID.text)
	if err != nil {
		return result, err
	}
	if (!key.NotBefore.IsZero() && now.Add(opts.Skew).Before(key.NotBefore)) || (!key.Expires.IsZero() && now.After(key.Expires.Add(opts.Skew))) {
		return result, fmt.Errorf("%w: key %s is not valid at this time", ErrInvalidSignature, key.ID)
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return result, fmt.Errorf("%w: key %s is not an Ed25519 key", ErrInvalidSignature, key.ID)
	}
	if ed25519.Verify(key.PublicKey, []byte(base), signature) {
		return result, nil
	}
	// Interoperability: the signature in draft-meunier-web-bot-auth-architecture-05 test vector
	// A.2.2 verifies only when the keyed Signature-Agent member is signed unquoted, although the
	// draft's printed signature base and RFC 9421 section 2.1.2 use the serialised (quoted) form.
	// Both forms encode the same value, so accepting either does not weaken verification.
	if legacyBase, err := signatureBase(r, *input.innerList, true); err == nil && legacyBase != base &&
		ed25519.Verify(key.PublicKey, []byte(legacyBase), signature) {
		return result, nil
	}
	return result, fmt.Errorf("%w: signature does not match", ErrInvalidSignature)
}

// unquoteSF turns a serialised sf-string component value back into its text.
func unquoteSF(value string) string {
	if item, err := parseItem(value); err == nil && item.value.kind == sfString {
		return item.value.text
	}
	return value
}

// signatureBase builds the RFC 9421 section 2.5 signature base. With unquoteKeyed set, string
// members selected with the key parameter are written without quotes (see verifyOne).
func signatureBase(r *http.Request, components sfInnerList, unquoteKeyed bool) (string, error) {
	var b strings.Builder
	seen := map[string]bool{}
	for _, component := range components.items {
		identifier := serializeItem(component)
		if seen[identifier] {
			return "", fmt.Errorf("%w: duplicate component %s", ErrInvalidSignature, identifier)
		}
		seen[identifier] = true
		value, err := componentValue(r, component)
		if err != nil {
			return "", err
		}
		if _, keyed := findParam(component.params, "key"); keyed && unquoteKeyed {
			value = unquoteSF(value)
		}
		b.WriteString(identifier)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteByte('\n')
	}
	b.WriteString(`"@signature-params": `)
	b.WriteString(serializeInnerList(components))
	return b.String(), nil
}

// componentValue returns the canonical value of a covered component (RFC 9421 section 2).
func componentValue(r *http.Request, component sfItem) (string, error) {
	name := component.value.text
	if strings.HasPrefix(name, "@") {
		if len(component.params) > 0 {
			return "", fmt.Errorf("%w: parameters on %s are not supported", ErrInvalidSignature, name)
		}
		switch name {
		case "@method":
			return r.Method, nil
		case "@authority":
			return authority(r), nil
		case "@scheme":
			return scheme(r), nil
		case "@target-uri":
			return scheme(r) + "://" + authority(r) + r.URL.RequestURI(), nil
		case "@path":
			if p := r.URL.EscapedPath(); p != "" {
				return p, nil
			}
			return "/", nil
		case "@query":
			return "?" + r.URL.RawQuery, nil
		case "@request-target":
			return r.URL.RequestURI(), nil
		}
		return "", fmt.Errorf("%w: unsupported component %s", ErrInvalidSignature, name)
	}

	if name != strings.ToLower(name) {
		return "", fmt.Errorf("%w: field names must be lowercase", ErrInvalidSignature)
	}
	values := r.Header.Values(name)
	if len(values) == 0 {
		return "", fmt.Errorf("%w: covered header %q is missing", ErrInvalidSignature, name)
	}
	key, hasKey := findParam(component.params, "key")
	for _, param := range component.params {
		if param.key != "key" {
			return "", fmt.Errorf("%w: parameter %q on %s is not supported", ErrInvalidSignature, param.key, name)
		}
	}
	if hasKey {
		if key.kind != sfString {
			return "", fmt.Errorf("%w: key parameter must be a string", ErrInvalidSignature)
		}
		members, err := parseDictionary(strings.Join(values, ", "))
		if err != nil {
			return "", fmt.Errorf("%w: %s is not a dictionary: %v", ErrInvalidSignature, name, err)
		}
		for _, m := range members {
			if m.key != key.text {
				continue
			}
			if m.innerList != nil {
				return serializeInnerList(*m.innerList), nil
			}
			return serializeItem(*m.item), nil
		}
		return "", fmt.Errorf("%w: %s has no member %q", ErrInvalidSignature, name, key.text)
	}
	trimmed := make([]string, len(values))
	for i, v := range values {
		trimmed[i] = strings.Trim(v, " \t")
	}
	return strings.Join(trimmed, ", "), nil
}

func authority(r *http.Request) string {
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	host = strings.ToLower(host)
	switch {
	case scheme(r) == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case scheme(r) == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	return host
}

func scheme(r *http.Request) string {
	if r.URL != nil && r.URL.Scheme != "" {
		return strings.ToLower(r.URL.Scheme)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// SignOptions configures [Sign].
type SignOptions struct {
	// Label is the signature label (default "sig1").
	Label string
	// SignatureAgent, if set, is sent as Signature-Agent: <Label>="<value>" and covered by the signature.
	SignatureAgent string
	// Created defaults to now; Validity defaults to 5 minutes.
	Created  time.Time
	Validity time.Duration
	// Nonce is optional; the draft recommends 64 random bytes, base64url-encoded.
	Nonce string
}

// Sign adds Web Bot Auth headers to an outgoing request: Signature-Input and Signature, plus
// Signature-Agent if opts.SignatureAgent is set. Use it when building an agent that should be
// verifiable by websites.
func Sign(r *http.Request, key ed25519.PrivateKey, opts SignOptions) error {
	if opts.Label == "" {
		opts.Label = "sig1"
	}
	if opts.Created.IsZero() {
		opts.Created = time.Now()
	}
	if opts.Validity == 0 {
		opts.Validity = 5 * time.Minute
	}
	if opts.SignatureAgent != "" {
		if _, err := url.Parse(opts.SignatureAgent); err != nil {
			return err
		}
		r.Header.Set("Signature-Agent", opts.Label+"="+serializeBareItem(sfBareItem{kind: sfString, text: opts.SignatureAgent}))
	}

	components := sfInnerList{items: []sfItem{{value: sfBareItem{kind: sfString, text: "@authority"}}}}
	if opts.SignatureAgent != "" {
		components.items = append(components.items, sfItem{
			value:  sfBareItem{kind: sfString, text: "signature-agent"},
			params: []sfParam{{key: "key", value: sfBareItem{kind: sfString, text: opts.Label}}},
		})
	}
	components.params = []sfParam{
		{key: "created", value: sfBareItem{kind: sfInteger, integer: opts.Created.Unix()}},
		{key: "keyid", value: sfBareItem{kind: sfString, text: Thumbprint(key.Public().(ed25519.PublicKey))}},
		{key: "alg", value: sfBareItem{kind: sfString, text: "ed25519"}},
		{key: "expires", value: sfBareItem{kind: sfInteger, integer: opts.Created.Add(opts.Validity).Unix()}},
	}
	if opts.Nonce != "" {
		components.params = append(components.params, sfParam{key: "nonce", value: sfBareItem{kind: sfString, text: opts.Nonce}})
	}
	components.params = append(components.params, sfParam{key: "tag", value: sfBareItem{kind: sfString, text: Tag}})

	base, err := signatureBase(r, components, false)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(key, []byte(base))
	r.Header.Set("Signature-Input", opts.Label+"="+serializeInnerList(components))
	r.Header.Set("Signature", opts.Label+"="+serializeBareItem(sfBareItem{kind: sfBytes, bytes: signature}))
	return nil
}
