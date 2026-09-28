package samesame

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/yaronf/httpsign"
)

// testRSAPSSPublic is the RFC 9421 B.1.2 public key used by Appendix E.1.
const testRSAPSSPublic = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----`

const testAgentIdentifier = "https://signature-agent.test/.well-known/http-message-signatures-directory"

// mapResolver resolves identifiers from a fixed map.
type mapResolver struct {
	dirs map[string]*Directory
	err  error
}

func (m mapResolver) Resolve(_ context.Context, id *url.URL) (*Directory, error) {
	if m.err != nil {
		return nil, m.err
	}
	d, ok := m.dirs[id.String()]
	if !ok {
		return nil, errors.New("no such directory")
	}
	return d, nil
}

func directoryOf(t *testing.T, pubs ...crypto.PublicKey) *Directory {
	t.Helper()

	var d Directory
	for _, pub := range pubs {
		k, err := jwk.Import[jwk.Key](pub)
		if err != nil {
			t.Fatalf("jwk.Import: %v", err)
		}
		id, err := Thumbprint(k)
		if err != nil {
			t.Fatalf("Thumbprint: %v", err)
		}
		d.Keys = append(d.Keys, Key{ID: id, JWK: k})
	}
	return &d
}

func loadRSAPSSPublic(t *testing.T) crypto.PublicKey {
	t.Helper()

	block, _ := pem.Decode([]byte(testRSAPSSPublic))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("can't parse RSA-PSS key: %v", err)
	}
	return pub
}

func TestVerifyProtocolVectors(t *testing.T) {
	t.Parallel()

	edPub, _ := loadEd25519(t)
	rsaPub := loadRSAPSSPublic(t)
	resolver := mapResolver{dirs: map[string]*Directory{
		testAgentIdentifier: directoryOf(t, edPub, rsaPub),
	}}

	for _, tt := range []struct {
		name           string
		signatureAgent string
		signatureInput string
		signature      string
		wantKeyID      string
		now            time.Time
	}{
		{
			name:           "E.1.1 rsa-pss dictionary",
			signatureAgent: `agent2="https://signature-agent.test"`,
			signatureInput: `sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=4889289600;nonce="wcfPQPh7SzkvrIVvhD00vNk9PkxJNY2NVbYl2PVBB4zmUoluSwE7W6bPtF60QA3k8g06FU7PPCD+J58YofY1zg==";tag="web-bot-auth"`,
			signature:      `sig2=:gHzpLNeHaHIO19NaJH9YMW5dcVSi2s0wOMBr6p18vcofS106sfC4KBIS0/szPlBBd1vIcyQ88B6CTEWIhRAiVrb9zfX0mx1aG12CSGWcYkSirHeyTxhbuJvXd27ed6skWoy4PjXItq38936ivUQjfdIwXh1aX6HxkAC3vRnEdSNfntkLWeEuIQ5BLIOBGE39fSwg27Qjq6OVWYas/9/aFUr3HA34MXWYdp+//cvlEKDp3kRoLOw9ro0AOr6srHrTeEtxon2afcws1aZVSlPdd2fZSEIGmw9HAHLDCEkFTERu1gH2k/zIEqgy7CAYXI9E5slog0cLg/Vc6+f8gih33g==:`,
			wantKeyID:      "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA",
			now:            time.Unix(1735690000, 0),
		},
		{
			name:           "E.1.2 rsa-pss legacy string",
			signatureAgent: `"https://signature-agent.test"`,
			signatureInput: `sig2=("@authority" "signature-agent");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=1735693200;nonce="XSHtZVCThSIAksXsH9WBs6AtxtXC0eQGiIcUGSoJstFs8lAWakjhrfwzLhyjtme5iXMZvmFWqDEs6cT3Jf+BbQ==";tag="web-bot-auth"`,
			signature:      `sig2=:I1QWNzGXdP1a4dSvOHLCVOOanEYHDk+ZsVxM9MLX/p4ko69ghKwR5EOtAD96g7g4GWP7lmpM/jFAf9q8EFRDTPLjUXySwMv4YPgabv2LQihTJG2y8a2m6IGltyruwQNiqSJVUuRaG9+b17CGmAMFZh30X6GXLdQJrCARpeTqPwp2DC+a8haDE/VE5EruqzjA5/2mKwvrkzkSqeW5tOVtFwWRRHIOidquf/8Je6kM9mhgkg4arudLA5SL4wyyYE1jURIgcOl8agrfdJ5Def23DIRtiOLRa8jT9cpTLFAuFHN+mrZA/LH9h0gSIg1cPb+0cMASee5uku1KjWcFer7jWA==:`,
			wantKeyID:      "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA",
			now:            time.Unix(1735690000, 0),
		},
		{
			name:           "E.2.1 ed25519 dictionary",
			signatureAgent: `agent2="https://signature-agent.test"`,
			signatureInput: `sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"`,
			signature:      `sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:`,
			wantKeyID:      testEd25519KeyID,
			now:            time.Unix(1735690000, 0),
		},
		{
			name:           "E.2.2 ed25519 legacy string",
			signatureAgent: `"https://signature-agent.test"`,
			signatureInput: `sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`,
			signature:      `sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:`,
			wantKeyID:      testEd25519KeyID,
			now:            time.Unix(1735690000, 0),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v, err := NewVerifier(VerifierOptions{
				Resolver: resolver,
				// E.x.1 are valid for about a century so they do not age.
				MaxValidity: 200 * 365 * 24 * time.Hour,
				Now:         func() time.Time { return tt.now },
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			r.Header.Set(HeaderSignatureAgent, tt.signatureAgent)
			r.Header.Set("Signature-Input", tt.signatureInput)
			r.Header.Set("Signature", tt.signature)

			res, err := v.Verify(r)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.KeyID != tt.wantKeyID {
				t.Errorf("keyid: want %s, got %s", tt.wantKeyID, res.KeyID)
			}
			if res.Identifier == nil || res.Identifier.String() != testAgentIdentifier {
				t.Errorf("identifier: want %s, got %v", testAgentIdentifier, res.Identifier)
			}
			if res.Label != "sig2" {
				t.Errorf("label: want sig2, got %s", res.Label)
			}
		})
	}
}

// signCustom signs r with httpsign directly, for requests Signer would never
// produce.
func signCustom(t *testing.T, r *http.Request, key crypto.Signer, label string, cfg *httpsign.SignConfig, fields *httpsign.Fields) {
	t.Helper()

	newS, err := signerFunc(key)
	if err != nil {
		t.Fatalf("signerFunc: %v", err)
	}
	s, err := newS(cfg, *fields)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	in, sig, err := httpsign.SignRequest(label, *s, r)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	r.Header.Add("Signature-Input", in)
	r.Header.Add("Signature", sig)
}

type failingNonceStore struct{}

func (failingNonceStore) CheckAndRecord(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("database on fire")
}

func TestVerify(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t, "ed25519")
	other := mustGenerate(t, "ed25519")
	keyID := mustThumbprint(t, key.Public())
	good := mapResolver{dirs: map[string]*Directory{testAgentIdentifier: directoryOf(t, key.Public())}}

	// sign returns a request signed by a default Signer for key.
	sign := func(t *testing.T, opts SignerOptions) *http.Request {
		t.Helper()
		if opts.AgentOrigin == "" {
			opts.AgentOrigin = testAgentOrigin
		}
		s, err := NewSigner(key, opts)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		if err := s.Sign(r); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return r
	}

	profile := func() *httpsign.SignConfig {
		return httpsign.NewSignConfig().SetTag(TagWebBotAuth).SetKeyID(keyID).SetExpiresAfter(3600)
	}

	for _, tt := range []struct {
		name           string
		opts           VerifierOptions
		request        func(t *testing.T) *http.Request
		wantOutcome    Outcome
		err            error
		wantIdentifier bool
		wantStatus     int
	}{
		{
			name:           "signed by Signer",
			opts:           VerifierOptions{Resolver: good},
			request:        func(t *testing.T) *http.Request { return sign(t, SignerOptions{}) },
			wantOutcome:    OutcomeVerified,
			wantIdentifier: true,
		},
		{
			name:           "member key differs from label",
			opts:           VerifierOptions{Resolver: good},
			request:        func(t *testing.T) *http.Request { return sign(t, SignerOptions{Label: "sig2", AgentKey: "agent2"}) },
			wantOutcome:    OutcomeVerified,
			wantIdentifier: true,
		},
		{
			name: "unsigned",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				return httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			},
			wantOutcome: OutcomeUnverified,
			err:         ErrNoSignature,
		},
		{
			name: "signature with another tag",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
				signCustom(t, r, key, "sig1", httpsign.NewSignConfig().SetTag("other").SetKeyID(keyID), httpsign.NewFields().AddHeader("@authority"))
				return r
			},
			wantOutcome: OutcomeUnverified,
			err:         ErrNoSignature,
		},
		{
			name: "malformed Signature-Input",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Set("Signature-Input", `sig1=("@authority"`)
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrMalformedSignature,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name: "malformed Signature-Agent",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Set(HeaderSignatureAgent, `sig1="unterminated`)
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrMalformedSignatureAgent,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name: "plaintext HTTP",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.TLS = nil
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrInsecureTransport,
		},
		{
			name: "plaintext HTTP allowed",
			opts: VerifierOptions{Resolver: good, AllowInsecure: true},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.TLS = nil
				return r
			},
			wantOutcome:    OutcomeVerified,
			wantIdentifier: true,
		},
		{
			name: "TLS terminated by a proxy",
			opts: VerifierOptions{Resolver: good, Scheme: func(r *http.Request) string { return r.Header.Get("X-Forwarded-Proto") }},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.TLS = nil
				r.Header.Set("X-Forwarded-Proto", "https")
				return r
			},
			wantOutcome:    OutcomeVerified,
			wantIdentifier: true,
		},
		{
			name: "missing expires",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Del("Signature-Input")
				r.Header.Del("Signature")
				signCustom(t, r, key, "sig1", httpsign.NewSignConfig().SetTag(TagWebBotAuth).SetKeyID(keyID),
					httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", "sig1"))
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrProfile,
		},
		{
			name: "missing keyid",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Del("Signature-Input")
				r.Header.Del("Signature")
				signCustom(t, r, key, "sig1", httpsign.NewSignConfig().SetTag(TagWebBotAuth).SetExpiresAfter(60),
					httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", "sig1"))
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrProfile,
		},
		{
			name: "authority not covered",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Del("Signature-Input")
				r.Header.Del("Signature")
				signCustom(t, r, key, "sig1", profile(), httpsign.NewFields().AddHeader("@method").AddDictHeader("signature-agent", "sig1"))
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrProfile,
		},
		{
			name: "target-uri instead of authority",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Del("Signature-Input")
				r.Header.Del("Signature")
				signCustom(t, r, key, "sig1", profile(), httpsign.NewFields().AddHeader("@target-uri").AddDictHeader("signature-agent", "sig1"))
				return r
			},
			wantOutcome:    OutcomeVerified,
			wantIdentifier: true,
		},
		{
			name:        "expired",
			opts:        VerifierOptions{Resolver: good, Now: func() time.Time { return time.Now().Add(2 * time.Hour) }},
			request:     func(t *testing.T) *http.Request { return sign(t, SignerOptions{}) },
			wantOutcome: OutcomeInvalid,
			err:         ErrExpired,
		},
		{
			name:        "created in the future",
			opts:        VerifierOptions{Resolver: good, Now: func() time.Time { return time.Now().Add(-time.Hour) }},
			request:     func(t *testing.T) *http.Request { return sign(t, SignerOptions{}) },
			wantOutcome: OutcomeInvalid,
			err:         ErrNotYetValid,
		},
		{
			// expires is inside the clock skew, so only the ordering check
			// can catch it.
			name: "expires before created",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Del("Signature-Input")
				r.Header.Del("Signature")
				signCustom(t, r, key, "sig1",
					httpsign.NewSignConfig().SetTag(TagWebBotAuth).SetKeyID(keyID).SetExpires(time.Now().Add(-10*time.Second).Unix()),
					httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", "sig1"))
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrProfile,
		},
		{
			name:        "validity longer than policy",
			opts:        VerifierOptions{Resolver: good, MaxValidity: 30 * time.Minute},
			request:     func(t *testing.T) *http.Request { return sign(t, SignerOptions{}) },
			wantOutcome: OutcomeInvalid,
			err:         ErrValidityTooLong,
		},
		{
			name: "tampered authority",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Host = "evil.example"
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrBadSignature,
		},
		{
			name: "tampered Signature-Agent",
			opts: VerifierOptions{Resolver: mapResolver{dirs: map[string]*Directory{
				testAgentIdentifier:                    directoryOf(t, key.Public()),
				"https://evil.example" + WellKnownPath: directoryOf(t, key.Public()),
			}}},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Set(HeaderSignatureAgent, `sig1="https://evil.example"`)
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrBadSignature,
		},
		{
			name: "covered member missing from header",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{Label: "sig2", AgentKey: "agent2"})
				// Relabeling the member breaks the covered ;key= lookup;
				// the verifier must not fall back to the signature label.
				r.Header.Set(HeaderSignatureAgent, `sig2="https://signature-agent.test"`)
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrProfile,
		},
		{
			name: "Signature-Agent not covered and no static key",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Del("Signature-Input")
				r.Header.Del("Signature")
				signCustom(t, r, key, "sig1", profile(), httpsign.NewFields().AddHeader("@authority"))
				return r
			},
			wantOutcome: OutcomeUnverified,
			err:         ErrKeyUnknown,
		},
		{
			name: "Signature-Agent not covered with static key",
			opts: VerifierOptions{StaticKeys: []crypto.PublicKey{key.Public()}},
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
				signCustom(t, r, key, "sig1", profile(), httpsign.NewFields().AddHeader("@authority"))
				return r
			},
			wantOutcome: OutcomeVerified,
		},
		{
			name:        "key not in directory",
			opts:        VerifierOptions{Resolver: mapResolver{dirs: map[string]*Directory{testAgentIdentifier: directoryOf(t, other.Public())}}},
			request:     func(t *testing.T) *http.Request { return sign(t, SignerOptions{}) },
			wantOutcome: OutcomeUnverified,
			err:         ErrKeyUnknown,
		},
		{
			name:        "discovery failure",
			opts:        VerifierOptions{Resolver: mapResolver{err: errors.New("connection refused")}},
			request:     func(t *testing.T) *http.Request { return sign(t, SignerOptions{}) },
			wantOutcome: OutcomeUnverified,
			err:         ErrDiscovery,
		},
		{
			// Protocol draft Section 6.10: verify with a key held
			// otherwise, but do not attribute to the URL.
			name:        "discovery failure falls back to static key",
			opts:        VerifierOptions{Resolver: mapResolver{err: errors.New("connection refused")}, StaticKeys: []crypto.PublicKey{key.Public()}},
			request:     func(t *testing.T) *http.Request { return sign(t, SignerOptions{}) },
			wantOutcome: OutcomeVerified,
		},
		{
			name:        "no resolver configured",
			opts:        VerifierOptions{},
			request:     func(t *testing.T) *http.Request { return sign(t, SignerOptions{}) },
			wantOutcome: OutcomeUnverified,
			err:         ErrKeyUnknown,
		},
		{
			name: "hmac is refused",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				r.Header.Del("Signature-Input")
				r.Header.Del("Signature")
				s, err := httpsign.NewHMACSHA256Signer([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), profile(),
					*httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", "sig1"))
				if err != nil {
					t.Fatalf("NewHMACSHA256Signer: %v", err)
				}
				in, sig, err := httpsign.SignRequest("sig1", *s, r)
				if err != nil {
					t.Fatalf("SignRequest: %v", err)
				}
				r.Header.Set("Signature-Input", in)
				r.Header.Set("Signature", sig)
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrBadSignature,
		},
		{
			name:        "nonce required but absent",
			opts:        VerifierOptions{Resolver: good, NonceStore: NewMemoryNonceStore(0), RequireNonce: true},
			request:     func(t *testing.T) *http.Request { return sign(t, SignerOptions{DisableNonce: true}) },
			wantOutcome: OutcomeInvalid,
			err:         ErrNonceRequired,
		},
		{
			name:        "nonce store unavailable",
			opts:        VerifierOptions{Resolver: good, NonceStore: failingNonceStore{}},
			request:     func(t *testing.T) *http.Request { return sign(t, SignerOptions{}) },
			wantOutcome: OutcomeUnverified,
			err:         ErrNonceStore,
		},
		{
			name: "too many signatures",
			opts: VerifierOptions{Resolver: good, MaxSignatures: 1},
			request: func(t *testing.T) *http.Request {
				r := sign(t, SignerOptions{})
				s, err := NewSigner(key, SignerOptions{AgentOrigin: testAgentOrigin, Label: "sig2"})
				if err != nil {
					t.Fatalf("NewSigner: %v", err)
				}
				if err := s.Sign(r); err != nil {
					t.Fatalf("Sign: %v", err)
				}
				return r
			},
			wantOutcome: OutcomeInvalid,
			err:         ErrTooManySignatures,
		},
		{
			name: "one bad signature and one good one",
			opts: VerifierOptions{Resolver: good},
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
				r.Header.Set(HeaderSignatureAgent, `sig1="https://signature-agent.test"`)
				signCustom(t, r, other, "bad", profile(), httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", "sig1"))
				signCustom(t, r, key, "good", profile(), httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", "sig1"))
				return r
			},
			wantOutcome:    OutcomeVerified,
			wantIdentifier: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v, err := NewVerifier(tt.opts)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			res, err := v.Verify(tt.request(t))

			if got := OutcomeOf(err); got != tt.wantOutcome {
				t.Logf("err: %v", err)
				t.Fatalf("outcome: want %s, got %s", tt.wantOutcome, got)
			}
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Logf("want: %v", tt.err)
				t.Logf("got:  %v", err)
				t.Error("got wrong error")
			}
			if tt.wantStatus != 0 && StatusCode(err) != tt.wantStatus {
				t.Errorf("status: want %d, got %d", tt.wantStatus, StatusCode(err))
			}

			if tt.wantOutcome != OutcomeVerified {
				if res != nil {
					t.Errorf("unexpected result %+v", res)
				}
				return
			}

			if res.KeyID != keyID {
				t.Errorf("keyid: want %s, got %s", keyID, res.KeyID)
			}
			switch {
			case tt.wantIdentifier && (res.Identifier == nil || res.Identifier.String() != testAgentIdentifier):
				t.Errorf("identifier: want %s, got %v", testAgentIdentifier, res.Identifier)
			case !tt.wantIdentifier && res.Identifier != nil:
				t.Errorf("identifier: want none, got %s", res.Identifier)
			}
		})
	}
}

func TestVerifyReplay(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t, "ed25519")
	s, err := NewSigner(key, SignerOptions{AgentOrigin: testAgentOrigin})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	v, err := NewVerifier(VerifierOptions{
		Resolver:   mapResolver{dirs: map[string]*Directory{testAgentIdentifier: directoryOf(t, key.Public())}},
		NonceStore: NewMemoryNonceStore(0),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err := s.Sign(r); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := v.Verify(r); err != nil {
		t.Fatalf("first Verify: %v", err)
	}

	_, err = v.Verify(r)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("second Verify: want %v, got %v", ErrReplay, err)
	}
	if StatusCode(err) != http.StatusTooManyRequests {
		t.Errorf("status: want 429, got %d", StatusCode(err))
	}
}

func TestNewVerifierRejectsTestKeys(t *testing.T) {
	t.Parallel()

	pub, _ := loadEd25519(t)

	if _, err := NewVerifier(VerifierOptions{StaticKeys: []crypto.PublicKey{pub}}); !errors.Is(err, ErrTestKey) {
		t.Errorf("want %v, got %v", ErrTestKey, err)
	}
	if _, err := NewVerifier(VerifierOptions{StaticKeys: []crypto.PublicKey{pub}, AllowTestKeys: true}); err != nil {
		t.Errorf("AllowTestKeys: %v", err)
	}
	if _, err := NewVerifier(VerifierOptions{RequireNonce: true}); err == nil {
		t.Error("RequireNonce without NonceStore was accepted")
	}
}

func mustThumbprint(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()

	k, err := jwk.Import[jwk.Key](pub)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	id, err := Thumbprint(k)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return id
}

func FuzzVerify(f *testing.F) {
	f.Add(`agent2="https://signature-agent.test"`,
		`sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
		`sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:`)
	f.Add(`"https://signature-agent.test"`, `sig2=("signature-agent");tag="web-bot-auth"`, `sig2=:AA==:`)
	f.Add(``, `a=();tag="web-bot-auth";keyid="x";created=1;expires=2`, `a=:AA==:`)

	pub, _ := ed25519Public()
	v, err := NewVerifier(VerifierOptions{
		Resolver:      mapResolver{dirs: map[string]*Directory{testAgentIdentifier: {Keys: []Key{pub}}}},
		MaxValidity:   200 * 365 * 24 * time.Hour,
		Now:           func() time.Time { return time.Unix(1735690000, 0) },
		AllowTestKeys: true,
	})
	if err != nil {
		f.Fatalf("NewVerifier: %v", err)
	}

	f.Fuzz(func(t *testing.T, agent, input, sig string) {
		r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		r.Header.Set(HeaderSignatureAgent, agent)
		r.Header.Set("Signature-Input", input)
		r.Header.Set("Signature", sig)

		res, err := v.Verify(r)
		if (res == nil) == (err == nil) {
			t.Fatalf("want exactly one of result and error, got %+v, %v", res, err)
		}
	})
}

// ed25519Public returns the RFC 9421 B.1.4 key as a directory Key without a
// *testing.T, for fuzz setup.
func ed25519Public() (Key, error) {
	k, err := jwk.ParseKey([]byte(testEd25519JWK))
	if err != nil {
		return Key{}, err
	}
	return Key{ID: testEd25519KeyID, JWK: k}, nil
}
