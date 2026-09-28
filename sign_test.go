package samesame

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/yaronf/httpsign"
)

const testAgentOrigin = "https://signature-agent.test"

func mustGenerate(t *testing.T, name string) crypto.Signer {
	t.Helper()

	var (
		k   crypto.Signer
		err error
	)
	switch name {
	case "ed25519":
		_, k, err = ed25519.GenerateKey(rand.Reader)
	case "p256":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		k, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "rsa":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("unknown key type %q", name)
	}
	if err != nil {
		t.Fatalf("can't generate %s key: %v", name, err)
	}
	return k
}

// verifySigned checks a request signed by Signer: the web-bot-auth profile
// parameters, and the signature itself via httpsign.
func verifySigned(t *testing.T, r *http.Request, pub crypto.PublicKey, label, agentKey string, expiry time.Duration, wantNonce bool) {
	t.Helper()

	details, err := httpsign.RequestDetails(label, r)
	if err != nil {
		t.Fatalf("RequestDetails: %v", err)
	}

	k, err := jwk.Import[jwk.Key](pub)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	wantKeyID, err := Thumbprint(k)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}

	if details.KeyID == nil || *details.KeyID != wantKeyID {
		t.Errorf("keyid: want %s, got %v", wantKeyID, details.KeyID)
	}
	if details.Tag == nil || *details.Tag != TagWebBotAuth {
		t.Errorf("tag: want %s, got %v", TagWebBotAuth, details.Tag)
	}
	if details.Created == nil || details.Expires == nil {
		t.Fatalf("created/expires missing: %+v", details)
	}
	if got := details.Expires.Sub(*details.Created); got != expiry {
		t.Errorf("expires - created: want %s, got %s", expiry, got)
	}
	if wantNonce {
		if details.Nonce == nil {
			t.Fatal("nonce missing")
		}
		raw, err := base64.RawURLEncoding.DecodeString(*details.Nonce)
		if err != nil || len(raw) != nonceSize {
			t.Errorf("nonce %q is not %d base64url bytes: %v", *details.Nonce, nonceSize, err)
		}
	} else if details.Nonce != nil {
		t.Errorf("unexpected nonce %q", *details.Nonce)
	}

	newV, _, err := verifierFunc(pub)
	if err != nil {
		t.Fatalf("verifierFunc: %v", err)
	}
	fields := httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", agentKey)
	v, err := newV(httpsign.NewVerifyConfig().SetAllowedTags([]string{TagWebBotAuth}), *fields)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := httpsign.VerifyRequest(label, *v, r); err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}

	sa, err := ParseSignatureAgent(r.Header)
	if err != nil {
		t.Fatalf("ParseSignatureAgent: %v", err)
	}
	m, ok := sa.Member(agentKey)
	if !ok || m.Err != nil || m.Value != testAgentOrigin {
		t.Errorf("Signature-Agent member %q: %+v", agentKey, m)
	}
}

func TestSignerKeyTypes(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"ed25519", "p256", "p384", "rsa"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key := mustGenerate(t, name)
			s, err := NewSigner(key, SignerOptions{AgentOrigin: testAgentOrigin})
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}

			r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			if err := s.Sign(r); err != nil {
				t.Fatalf("Sign: %v", err)
			}

			verifySigned(t, r, key.Public(), DefaultLabel, DefaultLabel, DefaultExpiry, true)
		})
	}
}

func TestSignerOptions(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		opts      SignerOptions
		label     string
		agentKey  string
		expiry    time.Duration
		wantNonce bool
	}{
		{
			name:      "defaults",
			opts:      SignerOptions{AgentOrigin: testAgentOrigin},
			label:     DefaultLabel,
			agentKey:  DefaultLabel,
			expiry:    DefaultExpiry,
			wantNonce: true,
		},
		{
			// Mirrors the Appendix E vectors: label sig2, member agent2.
			name:      "member key differs from label",
			opts:      SignerOptions{AgentOrigin: testAgentOrigin, Label: "sig2", AgentKey: "agent2"},
			label:     "sig2",
			agentKey:  "agent2",
			expiry:    DefaultExpiry,
			wantNonce: true,
		},
		{
			name:     "custom expiry without nonce",
			opts:     SignerOptions{AgentOrigin: testAgentOrigin, Expiry: 5 * time.Minute, DisableNonce: true},
			label:    DefaultLabel,
			agentKey: DefaultLabel,
			expiry:   5 * time.Minute,
		},
		{
			name:      "maximum expiry",
			opts:      SignerOptions{AgentOrigin: testAgentOrigin, Expiry: MaxExpiry},
			label:     DefaultLabel,
			agentKey:  DefaultLabel,
			expiry:    MaxExpiry,
			wantNonce: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, priv := loadEd25519(t)
			s, err := NewSigner(priv, tt.opts)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			if s.KeyID() != testEd25519KeyID {
				t.Errorf("KeyID: want %s, got %s", testEd25519KeyID, s.KeyID())
			}

			r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			if err := s.Sign(r); err != nil {
				t.Fatalf("Sign: %v", err)
			}

			verifySigned(t, r, priv.Public(), tt.label, tt.agentKey, tt.expiry, tt.wantNonce)
		})
	}
}

// The signature must be over the RFC 9421 Section 2.1.2 base for the
// Signature-Agent member, checked independently of httpsign.
func TestSignerSignatureBase(t *testing.T) {
	t.Parallel()

	pub, priv := loadEd25519(t)
	s, err := NewSigner(priv, SignerOptions{AgentOrigin: testAgentOrigin, Label: "sig2", AgentKey: "agent2"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err := s.Sign(r); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if got := r.Header.Get(HeaderSignatureAgent); got != `agent2="https://signature-agent.test"` {
		t.Errorf("Signature-Agent: got %s", got)
	}

	params := strings.TrimPrefix(r.Header.Get("Signature-Input"), "sig2=")
	base := "\"@authority\": example.com\n" +
		"\"signature-agent\";key=\"agent2\": \"https://signature-agent.test\"\n" +
		"\"@signature-params\": " + params

	sig := r.Header.Get("Signature")
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(sig, "sig2=:"), ":"))
	if err != nil {
		t.Fatalf("can't decode signature %q: %v", sig, err)
	}
	if !ed25519.Verify(pub, []byte(base), raw) {
		t.Fatalf("signature does not match base:\n%s", base)
	}
}

func TestNewSignerErrors(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		key  string
		opts SignerOptions
		err  error
	}{
		{name: "missing agent origin", key: "ed25519", opts: SignerOptions{}, err: ErrSignerConfig},
		{name: "http agent origin", key: "ed25519", opts: SignerOptions{AgentOrigin: "http://bot.test"}, err: ErrSignerConfig},
		{name: "agent origin with path", key: "ed25519", opts: SignerOptions{AgentOrigin: "https://bot.test/keys"}, err: ErrSignerConfig},
		{name: "expiry over 24h", key: "ed25519", opts: SignerOptions{AgentOrigin: testAgentOrigin, Expiry: MaxExpiry + time.Second}, err: ErrSignerConfig},
		{name: "negative expiry", key: "ed25519", opts: SignerOptions{AgentOrigin: testAgentOrigin, Expiry: -time.Minute}, err: ErrSignerConfig},
		{name: "uppercase label", key: "ed25519", opts: SignerOptions{AgentOrigin: testAgentOrigin, Label: "Sig1"}, err: ErrSignerConfig},
		{name: "agent key starting with digit", key: "ed25519", opts: SignerOptions{AgentOrigin: testAgentOrigin, AgentKey: "1agent"}, err: ErrSignerConfig},
		{name: "P-521 key", key: "p521", opts: SignerOptions{AgentOrigin: testAgentOrigin}, err: ErrUnsupportedKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewSigner(mustGenerate(t, tt.key), tt.opts)
			if !errors.Is(err, tt.err) {
				t.Logf("want: %v", tt.err)
				t.Logf("got:  %v", err)
				t.Error("got wrong error")
			}
		})
	}
}

func TestSignerExistingHeaders(t *testing.T) {
	t.Parallel()

	_, priv := loadEd25519(t)
	s, err := NewSigner(priv, SignerOptions{AgentOrigin: testAgentOrigin})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	for _, tt := range []struct {
		name          string
		agent         string
		signature     string
		err           error
		wantAgent     string // Signature-Agent after Sign, joined with ", "
		wantSignature int    // number of Signature header lines after Sign
	}{
		{
			name:          "other signer's member is kept",
			agent:         `other="https://other.test"`,
			wantAgent:     `other="https://other.test", sig1="https://signature-agent.test"`,
			wantSignature: 1,
		},
		{
			name:          "same member already present is reused",
			agent:         `sig1="https://signature-agent.test"`,
			wantAgent:     `sig1="https://signature-agent.test"`,
			wantSignature: 1,
		},
		{
			name:      "conflicting member",
			agent:     `sig1="https://other.test"`,
			err:       ErrLabelInUse,
			wantAgent: `sig1="https://other.test"`,
		},
		{
			name:          "label already signed leaves headers untouched",
			agent:         `other="https://other.test"`,
			signature:     `sig1=:AAAA:`,
			err:           ErrLabelInUse,
			wantAgent:     `other="https://other.test"`,
			wantSignature: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			if tt.agent != "" {
				r.Header.Set(HeaderSignatureAgent, tt.agent)
			}
			if tt.signature != "" {
				r.Header.Set("Signature", tt.signature)
			}

			err := s.Sign(r)
			if !errors.Is(err, tt.err) {
				t.Logf("want: %v", tt.err)
				t.Logf("got:  %v", err)
				t.Error("got wrong error")
			}

			if got := strings.Join(r.Header.Values(HeaderSignatureAgent), ", "); got != tt.wantAgent {
				t.Logf("want: %s", tt.wantAgent)
				t.Logf("got:  %s", got)
				t.Error("wrong Signature-Agent")
			}
			if got := len(r.Header.Values("Signature")); got != tt.wantSignature {
				t.Errorf("want %d Signature lines, got %d", tt.wantSignature, got)
			}
		})
	}
}

func TestSignerTransport(t *testing.T) {
	t.Parallel()

	_, priv := loadEd25519(t)
	s, err := NewSigner(priv, SignerOptions{AgentOrigin: testAgentOrigin})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	got := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Clone(r.Context())
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/path", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	cli := &http.Client{Transport: s.Transport(nil)}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if req.Header.Get("Signature") != "" || req.Header.Get(HeaderSignatureAgent) != "" {
		t.Error("Transport modified the caller's request")
	}

	// The server sees the request as it arrived, which is what a verifier
	// sees.
	verifySigned(t, <-got, priv.Public(), DefaultLabel, DefaultLabel, DefaultExpiry, true)
}
