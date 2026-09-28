package samesame

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEndToEnd runs the whole protocol over TLS: an agent signs with
// Signer.Transport, the origin verifies with Verifier, and the verifier
// discovers the agent's key through Fetcher from a DirectoryHandler.
func TestEndToEnd(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t, "ed25519")
	rotatedOut := mustGenerate(t, "ed25519")

	// The agent's key directory.
	dirSrv := newTestDirectoryServer(t, mustDirectoryHandler(t, key))
	agentOrigin := dirSrv.srv.URL
	agentID := agentOrigin + WellKnownPath

	// The origin, which reports what the verifier decided.
	pool := x509.NewCertPool()
	pool.AddCert(dirSrv.srv.Certificate())
	verifier, err := NewVerifier(VerifierOptions{
		Resolver: NewFetcher(FetcherOptions{
			TLSConfig:                 &tls.Config{RootCAs: pool},
			AllowPrivateAddresses:     true,
			VerifyDirectorySignatures: true,
		}),
		NonceStore: NewMemoryNonceStore(0),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := verifier.Verify(r)
		if err != nil {
			if OutcomeOf(err) == OutcomeUnverified {
				_ = WriteChallenge(w, ChallengeOptions{})
			}
			http.Error(w, err.Error(), StatusCode(err))
			return
		}
		_, _ = io.WriteString(w, res.Identifier.String()+" "+res.KeyID)
	}))
	t.Cleanup(origin.Close)

	get := func(t *testing.T, signer crypto.Signer) (int, string, http.Header) {
		t.Helper()

		transport := origin.Client().Transport
		if signer != nil {
			s, err := NewSigner(signer, SignerOptions{AgentOrigin: agentOrigin})
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			transport = s.Transport(transport)
		}

		resp, err := (&http.Client{Transport: transport}).Get(origin.URL + "/page")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(body)), resp.Header
	}

	t.Run("verified", func(t *testing.T) {
		code, body, _ := get(t, key)
		if code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", code, body)
		}
		if want := agentID + " " + mustThumbprint(t, key.Public()); body != want {
			t.Errorf("want %q, got %q", want, body)
		}
	})

	t.Run("unsigned gets a challenge", func(t *testing.T) {
		code, body, hdr := get(t, nil)
		if code != http.StatusForbidden {
			t.Fatalf("want 403, got %d: %s", code, body)
		}
		if hdr.Get("Accept-Signature") == "" {
			t.Error("no Accept-Signature challenge")
		}
	})

	t.Run("key not in the directory", func(t *testing.T) {
		code, body, _ := get(t, rotatedOut)
		if code != http.StatusForbidden || !strings.Contains(body, "unverified") {
			t.Fatalf("want 403 unverified, got %d: %s", code, body)
		}
	})

	t.Run("replayed request", func(t *testing.T) {
		s, err := NewSigner(key, SignerOptions{AgentOrigin: agentOrigin})
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		req, err := http.NewRequest(http.MethodGet, origin.URL+"/page", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Sign(req); err != nil {
			t.Fatalf("Sign: %v", err)
		}

		codes := make([]int, 2)
		for i := range codes {
			resp, err := origin.Client().Do(req.Clone(req.Context()))
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			_ = resp.Body.Close()
			codes[i] = resp.StatusCode
		}
		if codes[0] != http.StatusOK || codes[1] != http.StatusTooManyRequests {
			t.Errorf("want 200 then 429, got %v", codes)
		}
	})
}
