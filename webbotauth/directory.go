package webbotauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// WellKnownPath is where operators publish their key directory.
const WellKnownPath = "/.well-known/http-message-signatures-directory"

// Directory is a [KeySource] backed by an operator's published key directory (a JWKS document).
// Keys are cached for the TTL; an unknown keyid triggers at most one refetch per minute, so a
// flood of requests with made-up keyids cannot turn your server into a crawler of the
// operator's directory. A Directory is safe for concurrent use.
type Directory struct {
	url    string
	client *http.Client
	ttl    time.Duration
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]Key
	fetchedAt time.Time
	lastTry   time.Time
}

// NewDirectory returns a Directory for the given URL. Pass the URL from a trusted source (such as
// the aibouncer catalog), never one taken from the request being verified.
func NewDirectory(url string, client *http.Client) *Directory {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Directory{url: url, client: client, ttl: time.Hour, now: time.Now}
}

// Key implements KeySource.
func (d *Directory) Key(ctx context.Context, keyID string) (Key, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	stale := d.keys == nil || now.Sub(d.fetchedAt) > d.ttl
	_, known := d.keys[keyID]
	if (stale || !known) && now.Sub(d.lastTry) > time.Minute {
		d.lastTry = now
		keys, err := d.fetch(ctx)
		if err != nil && d.keys == nil {
			return Key{}, fmt.Errorf("webbotauth: fetch %s: %w", d.url, err)
		}
		if err == nil {
			d.keys, d.fetchedAt = keys, now
		}
	}
	key, ok := d.keys[keyID]
	if !ok {
		return Key{}, fmt.Errorf("%w: %s is not in %s", ErrUnknownKey, keyID, d.url)
	}
	return key, nil
}

func (d *Directory) fetch(ctx context.Context) (map[string]Key, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseDirectory(body)
}

// ParseDirectory parses a key directory and returns its Ed25519 keys indexed by thumbprint.
// Keys of other types are ignored. The thumbprint is always computed, never taken from the
// document's "kid", so a directory cannot alias one key under another's ID.
func ParseDirectory(data []byte) (map[string]Key, error) {
	var doc struct {
		Keys json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Nbf int64  `json:"nbf"`
		Exp int64  `json:"exp"`
	}
	var list []jwk
	if err := json.Unmarshal(doc.Keys, &list); err != nil {
		// Some directories (and the draft's own example) use a single object instead of an array.
		var single jwk
		if err := json.Unmarshal(doc.Keys, &single); err != nil {
			return nil, fmt.Errorf("webbotauth: directory has no keys array")
		}
		list = []jwk{single}
	}
	keys := map[string]Key{}
	for _, k := range list {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		pub := ed25519.PublicKey(raw)
		key := Key{ID: Thumbprint(pub), PublicKey: pub}
		if k.Nbf > 0 {
			key.NotBefore = time.Unix(k.Nbf, 0)
		}
		if k.Exp > 0 {
			key.Expires = time.Unix(k.Exp, 0)
		}
		keys[key.ID] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("webbotauth: directory has no Ed25519 keys")
	}
	return keys, nil
}

// StaticKeys is a KeySource holding a fixed set of keys, useful for tests and pinned keys.
type StaticKeys map[string]Key

// NewStaticKeys returns a StaticKeys containing the given public keys under their thumbprints.
func NewStaticKeys(pubs ...ed25519.PublicKey) StaticKeys {
	keys := StaticKeys{}
	for _, pub := range pubs {
		keys[Thumbprint(pub)] = Key{ID: Thumbprint(pub), PublicKey: pub}
	}
	return keys
}

// Key implements KeySource.
func (s StaticKeys) Key(_ context.Context, keyID string) (Key, error) {
	key, ok := s[keyID]
	if !ok {
		return Key{}, fmt.Errorf("%w: %s", ErrUnknownKey, keyID)
	}
	return key, nil
}
