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
	"time"
)

func TestDirectoryHandler(t *testing.T) {
	t.Parallel()

	k1, k2 := mustGenerate(t, "ed25519"), mustGenerate(t, "p256")
	h, err := NewDirectoryHandler([]crypto.Signer{k1, k2}, DirectoryHandlerOptions{Authorities: []string{"bot.test"}})
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

	t.Run("other hosts are refused", func(t *testing.T) {
		// Otherwise anyone could obtain signatures binding the bot's
		// keys to their own domain.
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://evil.test"+WellKnownPath, nil))
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("want 421, got %d", w.Code)
		}
		if len(w.Header().Values("Signature")) != 0 {
			t.Error("refused request carries signatures")
		}
	})

	t.Run("host case is canonicalized", func(t *testing.T) {
		// A fresh handler, so nothing is cached for bot.test yet.
		fresh, err := NewDirectoryHandler([]crypto.Signer{k1, k2}, DirectoryHandlerOptions{Authorities: []string{"bot.test"}})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "https://bot.test"+WellKnownPath, nil)
		r.Host = "BOT.test"
		w := httptest.NewRecorder()
		fresh.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", w.Code)
		}

		res := &http.Response{StatusCode: http.StatusOK, Header: w.Header(), Body: io.NopCloser(strings.NewReader(w.Body.String()))}
		d, _ := ParseDirectory(w.Body.Bytes(), DirectoryOptions{})
		req := httptest.NewRequest(http.MethodGet, "https://bot.test"+WellKnownPath, nil)
		NewFetcher(FetcherOptions{}).dropUnboundKeys(d, res, req, w.Body.Bytes())
		if len(d.Keys) != 2 {
			t.Errorf("signatures are not bound to the canonical host: %v", d.Invalid)
		}
	})
}

func TestNewDirectoryHandlerErrors(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t, "ed25519")
	for _, tt := range []struct {
		name string
		keys []crypto.Signer
		opts DirectoryHandlerOptions
	}{
		{name: "no keys", opts: DirectoryHandlerOptions{Authorities: []string{"bot.test"}}},
		{name: "P-521 key", keys: []crypto.Signer{mustGenerate(t, "p521")}, opts: DirectoryHandlerOptions{Authorities: []string{"bot.test"}}},
		{name: "no authorities", keys: []crypto.Signer{key}},
		{name: "empty authority", keys: []crypto.Signer{key}, opts: DirectoryHandlerOptions{Authorities: []string{""}}},
		{name: "authority with a path", keys: []crypto.Signer{key}, opts: DirectoryHandlerOptions{Authorities: []string{"bot.test/keys"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewDirectoryHandler(tt.keys, tt.opts); err == nil {
				t.Error("want an error, got none")
			}
		})
	}
}

func TestDirectoryHandlerSignatureCache(t *testing.T) {
	t.Parallel()

	hh, err := NewDirectoryHandler([]crypto.Signer{mustGenerate(t, "ed25519")}, DirectoryHandlerOptions{Authorities: []string{"a.test", "b.test"}})
	if err != nil {
		t.Fatalf("NewDirectoryHandler: %v", err)
	}
	h := hh.(*directoryHandler)
	now := time.Now()
	h.now = func() time.Time { return now }

	sig := func(host string) string {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://"+host+WellKnownPath, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d", host, w.Code)
		}
		return w.Header().Get("Signature-Input") + " " + w.Header().Get("Signature")
	}

	first := sig("a.test")

	// httpsign stamps created with the wall clock in whole seconds, and
	// Ed25519 is deterministic, so without this pause a fresh signature
	// would equal a cached one.
	time.Sleep(1100 * time.Millisecond)
	if again := sig("a.test"); again != first {
		t.Error("signatures were not reused within the refresh window")
	}
	if other := sig("b.test"); other == first {
		t.Error("two authorities share signatures")
	}

	now = now.Add(directorySignatureRefresh + time.Second)
	if refreshed := sig("a.test"); refreshed == first {
		t.Error("signatures were not refreshed after the refresh window")
	}
}
