package webbotauth

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// test-key-ed25519 from RFC 9421 appendix B.1.4.
const rfcPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`

const rfcPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`

func rfcKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pubBlock, _ := pem.Decode([]byte(rfcPublicKeyPEM))
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privBlock, _ := pem.Decode([]byte(rfcPrivateKeyPEM))
	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pub.(ed25519.PublicKey), priv.(ed25519.PrivateKey)
}

// testRequest is the RFC 9421 appendix B.2 test-request.
func testRequest() *http.Request {
	r := httptest.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", strings.NewReader(`{"hello": "world"}`))
	r.Host = "example.com"
	r.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
	r.Header.Set("Content-Length", "18")
	return r
}

func TestThumbprintMatchesDraftKeyID(t *testing.T) {
	pub, _ := rfcKeys(t)
	// keyid used for test-key-ed25519 in the draft's appendix A.2 test vectors.
	if got, want := Thumbprint(pub), "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"; got != want {
		t.Errorf("Thumbprint = %s, want %s", got, want)
	}
}

// RFC 9421 appendix B.2.6: the signature base must match byte for byte and the signature verify.
func TestRFC9421SignatureBaseEd25519(t *testing.T) {
	pub, _ := rfcKeys(t)
	r := testRequest()
	input := `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
	members, err := parseDictionary(input)
	if err != nil {
		t.Fatal(err)
	}
	base, err := signatureBase(r, *members[0].innerList, false)
	if err != nil {
		t.Fatal(err)
	}
	want := `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
	if base != want {
		t.Fatalf("signature base mismatch:\n got: %q\nwant: %q", base, want)
	}
	sig, _ := base64.StdEncoding.DecodeString("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==")
	if !ed25519.Verify(pub, []byte(base), sig) {
		t.Error("RFC 9421 B.2.6 signature does not verify")
	}
}

// Test vectors from draft-meunier-web-bot-auth-architecture-05 appendix A.2.
var draftVectors = []struct {
	name, agent, input, signature string
	now                           int64
}{
	{
		name:      "A.2.1 no Signature-Agent",
		input:     `sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="g0iqFa9e1ffijlyOScDkXpfSmTbYpRNSGPJrQ1It20ahwgzB3jOUcdgLgFxUg7RMtW4V8IILaKKtA+YuSyIgJQ==";tag="web-bot-auth"`,
		signature: `sig1=:FFASViSdcgsyaqqYiCnkHreeZzbNKcTzDvZC5uVlP/dn9IbWj8j0o4wKFTH3rBnUiSUBduwm1Gp5VlIPCp01Ag==:`,
		now:       1735689700,
	},
	{
		name:      "A.2.2 dictionary Signature-Agent",
		agent:     `agent2="https://signature-agent.test"`,
		input:     `sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="XeP72svPKNiGEg3aDE7WJuTpN69H08oMFqC8NLFy1MptpENAT3WZTYwK+MYdsFMlaqHCJGo9ZAhqer1NWY9Epg==";tag="web-bot-auth"`,
		signature: `sig2=:DGiW2ErlQh0hc8wY2FQdbnFd6CEmonyY8nlvECIJFaUSYYNvNvSsGyP99BUGtq51gA4ouXlkUwjnta084bpjCg==:`,
		now:       1735689700,
	},
	{
		name:      "A.2.3 legacy string Signature-Agent",
		agent:     `"https://signature-agent.test"`,
		input:     `sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`,
		signature: `sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:`,
		now:       1735689700,
	},
}

func signedTestRequest(agent, input, signature string) *http.Request {
	r := testRequest()
	if agent != "" {
		r.Header.Set("Signature-Agent", agent)
	}
	r.Header.Set("Signature-Input", input)
	r.Header.Set("Signature", signature)
	return r
}

func TestDraftTestVectors(t *testing.T) {
	pub, _ := rfcKeys(t)
	keys := NewStaticKeys(pub)
	for _, v := range draftVectors {
		t.Run(v.name, func(t *testing.T) {
			r := signedTestRequest(v.agent, v.input, v.signature)
			if !Signed(r) {
				t.Fatal("Signed() = false")
			}
			res, err := Verify(context.Background(), r, keys, Options{Now: func() time.Time { return time.Unix(v.now, 0) }})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if v.agent != "" && res.SignatureAgent != "https://signature-agent.test" {
				t.Errorf("SignatureAgent = %q", res.SignatureAgent)
			}
			if v.agent != "" {
				if agents := SignatureAgents(r.Header); len(agents) != 1 || agents[0] != "https://signature-agent.test" {
					t.Errorf("SignatureAgents = %v", agents)
				}
			}
		})
	}
}

// The A.2.2 vector's signature covers the unquoted member value even though the draft prints a
// quoted one; this pins down that the strict form is tried first and the compatible form second.
func TestKeyedMemberSerialisationVariants(t *testing.T) {
	pub, _ := rfcKeys(t)
	v := draftVectors[1]
	r := signedTestRequest(v.agent, v.input, v.signature)
	members, _ := parseDictionary(v.input)
	strict, _ := signatureBase(r, *members[0].innerList, false)
	compat, _ := signatureBase(r, *members[0].innerList, true)
	if !strings.Contains(strict, `"signature-agent";key="agent2": "https://signature-agent.test"`) {
		t.Errorf("strict base:\n%s", strict)
	}
	if !strings.Contains(compat, `"signature-agent";key="agent2": https://signature-agent.test`) {
		t.Errorf("compat base:\n%s", compat)
	}
	sig, _ := base64.StdEncoding.DecodeString("DGiW2ErlQh0hc8wY2FQdbnFd6CEmonyY8nlvECIJFaUSYYNvNvSsGyP99BUGtq51gA4ouXlkUwjnta084bpjCg==")
	if ed25519.Verify(pub, []byte(strict), sig) || !ed25519.Verify(pub, []byte(compat), sig) {
		t.Error("expected the published A.2.2 signature to match only the unquoted form")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	pub, _ := rfcKeys(t)
	keys := NewStaticKeys(pub)
	v := draftVectors[1]
	now := Options{Now: func() time.Time { return time.Unix(v.now, 0) }}

	cases := map[string]func(r *http.Request){
		"different host":            func(r *http.Request) { r.Host = "evil.example" },
		"different Signature-Agent": func(r *http.Request) { r.Header.Set("Signature-Agent", `agent2="https://evil.example"`) },
		"Signature-Agent removed":   func(r *http.Request) { r.Header.Del("Signature-Agent") },
		"flipped signature byte": func(r *http.Request) {
			r.Header.Set("Signature", strings.Replace(v.signature, "DGiW", "DGiX", 1))
		},
		"changed nonce": func(r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(v.input, `nonce="XeP7`, `nonce="AeP7`, 1))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := signedTestRequest(v.agent, v.input, v.signature)
			mutate(r)
			if _, err := Verify(context.Background(), r, keys, now); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("err = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestTimeWindow(t *testing.T) {
	pub, _ := rfcKeys(t)
	keys := NewStaticKeys(pub)
	v := draftVectors[2] // expires 1735693200
	for name, now := range map[string]int64{"expired": 1735693200 + 3600, "not yet created": 1735689600 - 3600} {
		r := signedTestRequest(v.agent, v.input, v.signature)
		_, err := Verify(context.Background(), r, keys, Options{Now: func() time.Time { return time.Unix(now, 0) }})
		if !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A.2.2 is valid for a century; MaxValidity is opt-in.
	long := draftVectors[1]
	r := signedTestRequest(long.agent, long.input, long.signature)
	_, err := Verify(context.Background(), r, keys, Options{Now: func() time.Time { return time.Unix(long.now, 0) }, MaxValidity: 24 * time.Hour})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("MaxValidity: err = %v", err)
	}
}

func TestUnknownKeyAndUnsigned(t *testing.T) {
	other, _, _ := ed25519.GenerateKey(nil)
	v := draftVectors[0]
	r := signedTestRequest(v.agent, v.input, v.signature)
	_, err := Verify(context.Background(), r, NewStaticKeys(other), Options{Now: func() time.Time { return time.Unix(v.now, 0) }})
	if !errors.Is(err, ErrUnknownKey) {
		t.Errorf("err = %v, want ErrUnknownKey", err)
	}

	plain := testRequest()
	if Signed(plain) {
		t.Error("unsigned request reported as signed")
	}
	if _, err := Verify(context.Background(), plain, NewStaticKeys(other), Options{}); !errors.Is(err, ErrNoSignature) {
		t.Errorf("err = %v, want ErrNoSignature", err)
	}

	// A valid RFC 9421 signature without the web-bot-auth tag is not a Web Bot Auth signature.
	untagged := testRequest()
	untagged.Header.Set("Signature-Input", `sig1=("@authority");created=1;keyid="x"`)
	untagged.Header.Set("Signature", `sig1=:AAAA:`)
	if _, err := Verify(context.Background(), untagged, NewStaticKeys(other), Options{}); !errors.Is(err, ErrNoSignature) {
		t.Errorf("untagged: err = %v, want ErrNoSignature", err)
	}
}

func TestSignRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	r := httptest.NewRequest("GET", "https://shop.example/products?id=7", nil)
	if err := Sign(r, priv, SignOptions{SignatureAgent: "https://agent.example", Nonce: "bm9uY2U"}); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(context.Background(), r, NewStaticKeys(pub), Options{})
	if err != nil {
		t.Fatalf("Verify: %v\nSignature-Input: %s", err, r.Header.Get("Signature-Input"))
	}
	if res.SignatureAgent != "https://agent.example" || res.KeyID != Thumbprint(pub) {
		t.Errorf("result = %+v", res)
	}
}

func TestDirectory(t *testing.T) {
	pub, _ := rfcKeys(t)
	x := base64.RawURLEncoding.EncodeToString(pub)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/http-message-signatures-directory+json")
		// "kid" deliberately lies: the thumbprint must be computed, not trusted.
		fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"someone-else","x":%q,"nbf":1700000000,"exp":4000000000},{"kty":"RSA","n":"x","e":"AQAB"}]}`, x)
	}))
	defer srv.Close()

	dir := NewDirectory(srv.URL+WellKnownPath, srv.Client())
	key, err := dir.Key(context.Background(), Thumbprint(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(pub) || key.Expires.Unix() != 4000000000 {
		t.Errorf("key = %+v", key)
	}
	if _, err := dir.Key(context.Background(), "someone-else"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("lookup by advertised kid: err = %v, want ErrUnknownKey", err)
	}
	for i := 0; i < 20; i++ {
		_, _ = dir.Key(context.Background(), fmt.Sprintf("made-up-%d", i))
	}
	if hits != 1 {
		t.Errorf("directory fetched %d times; unknown keyids must not trigger refetch storms", hits)
	}

	v := draftVectors[0]
	r := signedTestRequest(v.agent, v.input, v.signature)
	if _, err := Verify(context.Background(), r, dir, Options{Now: func() time.Time { return time.Unix(v.now, 0) }}); err != nil {
		t.Errorf("verify through directory: %v", err)
	}
}

func TestParseDirectorySingleObjectAndErrors(t *testing.T) {
	pub, _ := rfcKeys(t)
	x := base64.RawURLEncoding.EncodeToString(pub)
	keys, err := ParseDirectory([]byte(fmt.Sprintf(`{"keys":{"kty":"OKP","crv":"Ed25519","x":%q}}`, x)))
	if err != nil || len(keys) != 1 {
		t.Errorf("single-object directory: %v %v", keys, err)
	}
	for _, bad := range []string{`{}`, `{"keys":[]}`, `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"short"}]}`, `not json`} {
		if _, err := ParseDirectory([]byte(bad)); err == nil {
			t.Errorf("ParseDirectory(%s) should fail", bad)
		}
	}
}

func TestStructuredFieldEdgeCases(t *testing.T) {
	for _, bad := range []string{`a=(`, `a="unterminated`, `a=:not base64!:`, `A=1`, `a=1,`, `a=?2`, `a="\x"`} {
		if _, err := parseDictionary(bad); err == nil {
			t.Errorf("parseDictionary(%q) should fail", bad)
		}
	}
	members, err := parseDictionary(`a=1, b;x=?0, a=2, c=("x" y);p=-3.5`)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 3 || members[0].item.value.integer != 2 {
		t.Errorf("members = %+v", members)
	}
	if got := serializeInnerList(*members[2].innerList); got != `("x" y);p=-3.5` {
		t.Errorf("round trip = %s", got)
	}
}

func FuzzVerifyDoesNotPanic(f *testing.F) {
	for _, v := range draftVectors {
		f.Add(v.agent, v.input, v.signature)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	keys := NewStaticKeys(pub)
	f.Fuzz(func(t *testing.T, agent, input, signature string) {
		r := httptest.NewRequest("GET", "https://example.com/", nil)
		r.Header["Signature-Agent"] = []string{agent}
		r.Header["Signature-Input"] = []string{input}
		r.Header["Signature"] = []string{signature}
		_, _ = Verify(context.Background(), r, keys, Options{})
		_ = SignatureAgents(r.Header)
	})
}
