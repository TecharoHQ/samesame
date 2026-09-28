package samesame

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
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

	// testEd25519KeyID is the RFC 8037 thumbprint of the key above.
	testEd25519KeyID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
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

// Step 0 spike: confirm httpsign handles the httpsig-protocol-00 Appendix E.2
// request vectors.
func TestSpikeProtocolVectors(t *testing.T) {
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
			name:           "E.2.1 dictionary Signature-Agent",
			label:          "sig2",
			signatureAgent: `agent2="https://signature-agent.test"`,
			signatureInput: `sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"`,
			signature:      `sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:`,
			fields:         *httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", "agent2"),
		},
		{
			name:           "E.2.2 legacy string Signature-Agent",
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
			req.Header.Set("Signature-Agent", tt.signatureAgent)

			details, err := httpsign.RequestDetailsByTag(req, TagWebBotAuth)
			if err != nil {
				t.Fatalf("RequestDetailsByTag: %v", err)
			}
			if details.Label != tt.label {
				t.Errorf("label: want %q, got %q", tt.label, details.Label)
			}
			if details.KeyID == nil || *details.KeyID != testEd25519KeyID {
				t.Errorf("keyid: got %v", details.KeyID)
			}
			if details.Nonce == nil || details.Expires == nil || details.Created == nil {
				t.Errorf("missing nonce/created/expires: %+v", details)
			}

			cfg := httpsign.NewVerifyConfig().
				SetVerifyCreated(false).
				SetRejectExpired(false).
				SetAllowedTags([]string{TagWebBotAuth})
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
	req.Header.Set("Signature-Agent", `agent2="https://signature-agent.test"`)

	signer, err := httpsign.NewEd25519Signer(priv,
		httpsign.NewSignConfig().SetTag(TagWebBotAuth).SetKeyID("k").SetExpires(1735693200),
		*httpsign.NewFields().AddHeader("@authority").AddDictHeader("signature-agent", "agent2"))
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}

	sigInput, sig, err := httpsign.SignRequest("sig2", *signer, req)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	params := strings.TrimPrefix(sigInput, "sig2=")
	base := "\"@authority\": example.com\n" +
		"\"signature-agent\";key=\"agent2\": \"https://signature-agent.test\"\n" +
		"\"@signature-params\": " + params

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(sig, "sig2=:"), ":"))
	if err != nil {
		t.Fatalf("can't decode signature: %v", err)
	}

	if !ed25519.Verify(pub, []byte(base), raw) {
		t.Fatalf("httpsign signature does not match the RFC 9421 base:\n%s", base)
	}
}

// Step 0 spike: confirm httpsign verifies the httpsig-protocol-00 E.2.3 signed
// directory response, which covers "@authority";req and content-digest.
func TestSpikeDirectoryResponseVector(t *testing.T) {
	pub, _ := loadEd25519(t)

	const body = `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}`

	req := httptest.NewRequest(http.MethodGet, "https://signature-agent.test"+WellKnownPath, nil)
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":    []string{MediaTypeDirectory},
			"Content-Digest":  []string{"sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:"},
			"Signature-Input": []string{`binding=("@authority";req "content-digest");created=1735689600;expires=4889289600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";tag="http-message-signatures-directory"`},
			"Signature":       []string{"binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:"},
		},
		Body:    io.NopCloser(strings.NewReader(body)),
		Request: req,
	}

	if err := httpsign.ValidateContentDigestHeader(res.Header.Values("Content-Digest"), &res.Body, []string{httpsign.DigestSha256}); err != nil {
		t.Fatalf("ValidateContentDigestHeader: %v", err)
	}

	fields := *httpsign.NewFields().AddRequestComponent("@authority").AddHeader("content-digest")
	v, err := httpsign.NewEd25519Verifier(pub,
		httpsign.NewVerifyConfig().SetVerifyCreated(false).SetAllowedTags([]string{TagDirectory}),
		fields)
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}

	if err := httpsign.VerifyResponse("binding", *v, res, req); err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}

	otherReq := httptest.NewRequest(http.MethodGet, "https://evil.example"+WellKnownPath, nil)
	if err := httpsign.VerifyResponse("binding", *v, res, otherReq); err == nil {
		t.Fatal("VerifyResponse succeeded against a different @authority")
	}
}
