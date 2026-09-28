package samesame

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDirectoryHandler(t *testing.T) {
	t.Parallel()

	k1, k2 := mustGenerate(t, "ed25519"), mustGenerate(t, "p256")
	h, err := NewDirectoryHandler([]crypto.Signer{k1, k2}, DirectoryHandlerOptions{})
	if err != nil {
		t.Fatalf("NewDirectoryHandler: %v", err)
	}

	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "https://bot.test"+WellKnownPath, nil))
	body := get.Body.Bytes()

	t.Run("GET", func(t *testing.T) {
		if get.Code != http.StatusOK {
			t.Fatalf("status: want 200, got %d", get.Code)
		}
		if ct := get.Header().Get("Content-Type"); ct != MediaTypeDirectory {
			t.Errorf("content type: got %s", ct)
		}
		if cc := get.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
			t.Errorf("cache control: got %s", cc)
		}

		sum := sha256.Sum256(body)
		if got, want := get.Header().Get("Content-Digest"), "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":"; got != want {
			t.Errorf("content digest: want %s, got %s", want, got)
		}

		if n := len(get.Header().Values("Signature")); n != 2 {
			t.Errorf("want one signature per key (2), got %d", n)
		}
		for _, in := range get.Header().Values("Signature-Input") {
			if !strings.Contains(in, `("@authority";req "content-digest")`) || !strings.Contains(in, `tag="http-message-signatures-directory"`) {
				t.Errorf("unexpected Signature-Input %s", in)
			}
		}

		if strings.Contains(string(body), `"d"`) {
			t.Fatal("directory leaks private key material")
		}

		dir, err := ParseDirectory(body, DirectoryOptions{})
		if err != nil {
			t.Fatalf("ParseDirectory: %v", err)
		}
		if len(dir.Keys) != 2 || len(dir.Invalid) != 0 {
			t.Fatalf("want 2 valid keys, got %d (invalid: %v)", len(dir.Keys), dir.Invalid)
		}
		for i, k := range []crypto.Signer{k1, k2} {
			if want := mustThumbprint(t, k.Public()); dir.Keys[i].ID != want {
				t.Errorf("key %d: want %s, got %s", i, want, dir.Keys[i].ID)
			}
			if kid, _ := dir.Keys[i].JWK.KeyID(); kid != dir.Keys[i].ID {
				t.Errorf("key %d: kid %q is not the thumbprint", i, kid)
			}
		}
	})

	t.Run("HEAD", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "https://bot.test"+WellKnownPath, nil))
		if w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Errorf("want 200 with no body, got %d with %d bytes", w.Code, w.Body.Len())
		}
	})

	t.Run("conditional GET", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "https://bot.test"+WellKnownPath, nil)
		r.Header.Set("If-None-Match", get.Header().Get("ETag"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotModified {
			t.Errorf("want 304, got %d", w.Code)
		}
	})

	t.Run("POST", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://bot.test"+WellKnownPath, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("want 405, got %d", w.Code)
		}
	})

	t.Run("signatures bind the request authority", func(t *testing.T) {
		res := &http.Response{StatusCode: http.StatusOK, Header: get.Header(), Body: io.NopCloser(strings.NewReader(string(body)))}
		dir, _ := ParseDirectory(body, DirectoryOptions{})

		f := NewFetcher(FetcherOptions{})
		for _, host := range []string{"bot.test", "evil.test"} {
			d := &Directory{Keys: dir.Keys}
			req := httptest.NewRequest(http.MethodGet, "https://"+host+WellKnownPath, nil)
			f.dropUnboundKeys(d, res, req, body)

			want := 2
			if host == "evil.test" {
				want = 0
			}
			if len(d.Keys) != want {
				t.Errorf("%s: want %d bound keys, got %d: %v", host, want, len(d.Keys), d.Invalid)
			}
		}
	})
}

func TestNewDirectoryHandlerErrors(t *testing.T) {
	t.Parallel()

	if _, err := NewDirectoryHandler(nil, DirectoryHandlerOptions{}); err == nil {
		t.Error("empty key list was accepted")
	}
	if _, err := NewDirectoryHandler([]crypto.Signer{mustGenerate(t, "p521")}, DirectoryHandlerOptions{}); err == nil {
		t.Error("P-521 key was accepted")
	}
}
