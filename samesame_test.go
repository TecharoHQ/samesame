package samesame

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yaronf/httpsign"
)

// Test keys from RFC 9421 Appendix B.1.4.
const (
	testEd25519Public = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`
	testEd25519Private = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`
)

func loadEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pubBlock, _ := pem.Decode([]byte(testEd25519Public))
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("can't parse public key: %v", err)
	}

	privBlock, _ := pem.Decode([]byte(testEd25519Private))
	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("can't parse private key: %v", err)
	}

	return pub.(ed25519.PublicKey), priv.(ed25519.PrivateKey)
}

// Step 0 spike: confirm httpsign handles the web-bot-auth architecture draft
// Appendix A.2 test vectors.
func TestSpikeArchitectureVectors(t *testing.T) {
	pub, _ := loadEd25519(t)

	for _, tt := range []struct {
		name           string
		label          string
		signatureAgent string
		signatureInput string
		signature      string
		fields         httpsign.Fields
	}{
		{
			name:           "A.2.1 no Signature-Agent",
			label:          "sig1",
			signatureInput: `sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="mYotfW3CUjI68sbGw6oKd7kyXqPjZEtU8xFPGWFrqOAf5qC6MDe3pys3SWWCudB0MvwslHy32WXUpkR7u0lt/w==";tag="web-bot-auth"`,
			signature:      `sig1=:+NA/cssf4Y2bQTMTkyvTGRCaVzp9quyUevdwwMtMOWhhOOZ2T1subBj0BtvdnrpDEuwSAbiTeElXDzHL3WWKCw==:`,
			fields:         httpsign.Headers("@authority"),
		},
		{
			// The -04 draft prints this vector with the dictionary form of
			// Signature-Agent ("signature-agent";key="sig2"), but the signature
			// bytes were computed over the older string form. This is the form
			// the signature actually verifies against.
			name:           "A.2.2 with Signature-Agent (legacy string form)",
			label:          "sig2",
			signatureAgent: `"https://signature-agent.test"`,
			signatureInput: `sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`,
			signature:      `sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:`,
			fields:         httpsign.Headers("@authority", "signature-agent"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			req.Header.Set("Signature-Input", tt.signatureInput)
			req.Header.Set("Signature", tt.signature)
			if tt.signatureAgent != "" {
				req.Header.Set("Signature-Agent", tt.signatureAgent)
			}

			details, err := httpsign.RequestDetailsByTag(req, "web-bot-auth")
			if err != nil {
				t.Fatalf("RequestDetailsByTag: %v", err)
			}
			if details.Label != tt.label {
				t.Errorf("label: want %q, got %q", tt.label, details.Label)
			}
			if details.KeyID == nil || *details.KeyID != "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U" {
				t.Errorf("keyid: got %v", details.KeyID)
			}
			if details.Nonce == nil || details.Expires == nil || details.Created == nil {
				t.Errorf("missing nonce/created/expires: %+v", details)
			}

			cfg := httpsign.NewVerifyConfig().
				SetVerifyCreated(false).
				SetRejectExpired(false).
				SetAllowedTags([]string{"web-bot-auth"})
			v, err := httpsign.NewEd25519Verifier(pub, cfg, tt.fields)
			if err != nil {
				t.Fatalf("NewEd25519Verifier: %v", err)
			}

			if err := httpsign.VerifyRequest(tt.label, *v, req); err != nil {
				t.Fatalf("VerifyRequest: %v", err)
			}
		})
	}
}

// Step 0 spike: confirm httpsign builds the RFC 9421 Section 2.1.2 signature
// base for a dictionary member component, checked against stdlib ed25519.
func TestSpikeDictMemberBase(t *testing.T) {
	pub, priv := loadEd25519(t)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("Signature-Agent", `sig2="https://signature-agent.test"`)

	signer, err := httpsign.NewEd25519Signer(priv,
		httpsign.NewSignConfig().SetTag("web-bot-auth").SetKeyID("k").SetExpires(1735693200),
		*httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", "sig2"))
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}

	sigInput, sig, err := httpsign.SignRequest("sig2", *signer, req)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	params := strings.TrimPrefix(sigInput, "sig2=")
	base := "\"@authority\": example.com\n" +
		"\"signature-agent\";key=\"sig2\": \"https://signature-agent.test\"\n" +
		"\"@signature-params\": " + params

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(sig, "sig2=:"), ":"))
	if err != nil {
		t.Fatalf("can't decode signature: %v", err)
	}

	if !ed25519.Verify(pub, []byte(base), raw) {
		t.Fatalf("httpsign signature does not match the RFC 9421 base:\n%s", base)
	}
}

// Step 0 spike: confirm httpsign can sign and verify a response covering
// "@authority";req, which the directory draft needs.
func TestSpikeResponseReqFlag(t *testing.T) {
	pub, priv := loadEd25519(t)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/.well-known/http-message-signatures-directory", nil)
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/http-message-signatures-directory+json"}},
		Request:    req,
	}

	fields := *httpsign.NewFields().AddRequestComponent("@authority")

	signer, err := httpsign.NewEd25519Signer(priv,
		httpsign.NewSignConfig().SetTag("http-message-signatures-directory").SetExpiresAfter(60).SetKeyID("test"),
		fields)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}

	sigInput, sig, err := httpsign.SignResponse("binding0", *signer, res, req)
	if err != nil {
		t.Fatalf("SignResponse: %v", err)
	}
	t.Logf("Signature-Input: %s", sigInput)
	res.Header.Set("Signature-Input", sigInput)
	res.Header.Set("Signature", sig)

	v, err := httpsign.NewEd25519Verifier(pub,
		httpsign.NewVerifyConfig().SetAllowedTags([]string{"http-message-signatures-directory"}),
		fields)
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}

	if err := httpsign.VerifyResponse("binding0", *v, res, req); err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}

	otherReq := httptest.NewRequest(http.MethodGet, "https://evil.example/.well-known/http-message-signatures-directory", nil)
	if err := httpsign.VerifyResponse("binding0", *v, res, otherReq); err == nil {
		t.Fatal("VerifyResponse succeeded against a different @authority")
	}
}
