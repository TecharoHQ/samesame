package samesame

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/yaronf/httpsign"
)

const (
	// DefaultDirectoryMaxAge is the default Cache-Control max-age of a served
	// directory.
	DefaultDirectoryMaxAge = time.Hour

	// DefaultDirectorySignatureLifetime is how long directory response
	// signatures stay valid. Appendix C.8 of the protocol draft recommends
	// lifetimes well beyond any republication interval.
	DefaultDirectorySignatureLifetime = 30 * 24 * time.Hour
)

// DirectoryHandlerOptions configures NewDirectoryHandler.
type DirectoryHandlerOptions struct {
	// MaxAge is sent as Cache-Control max-age. Defaults to
	// DefaultDirectoryMaxAge.
	MaxAge time.Duration

	// SignatureLifetime is the expires - created of each directory response
	// signature. Defaults to DefaultDirectorySignatureLifetime.
	SignatureLifetime time.Duration
}

type directoryHandler struct {
	body      []byte
	digest    string
	etag      string
	maxAge    time.Duration
	lifetime  time.Duration
	keyIDs    []string
	newSigner []newHTTPSigner
}

// NewDirectoryHandler returns an http.Handler that serves the public halves
// of keys as an HTTP Message Signatures Directory, for mounting at
// WellKnownPath. Each response carries one signature per key over
// ("@authority";req "content-digest") with tag
// http-message-signatures-directory, proving possession of the keys for the
// requested authority (protocol draft Appendix B.1).
func NewDirectoryHandler(keys []crypto.Signer, opts DirectoryHandlerOptions) (http.Handler, error) {
	if len(keys) == 0 {
		return nil, errors.New("samesame: directory needs at least one key")
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultDirectoryMaxAge
	}
	if opts.SignatureLifetime <= 0 {
		opts.SignatureLifetime = DefaultDirectorySignatureLifetime
	}

	h := &directoryHandler{maxAge: opts.MaxAge, lifetime: opts.SignatureLifetime}

	var jwks []jwk.Key
	for i, key := range keys {
		newS, err := signerFunc(key)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}

		// Import only the public half so private material can never be
		// served.
		pub, err := jwk.Import[jwk.Key](key.Public())
		if err != nil {
			return nil, fmt.Errorf("%w: key %d: %w", ErrUnsupportedKey, i, err)
		}
		id, err := Thumbprint(pub)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		if err := pub.Set(jwk.KeyIDKey, id); err != nil {
			return nil, fmt.Errorf("key %d: can't set kid: %w", i, err)
		}
		if err := pub.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
			return nil, fmt.Errorf("key %d: can't set use: %w", i, err)
		}

		jwks = append(jwks, pub)
		h.keyIDs = append(h.keyIDs, id)
		h.newSigner = append(h.newSigner, newS)
	}

	body, err := json.Marshal(struct {
		Keys []jwk.Key `json:"keys"`
	}{jwks})
	if err != nil {
		return nil, fmt.Errorf("samesame: can't serialize directory: %w", err)
	}
	h.body = body

	sum := sha256.Sum256(body)
	h.digest = "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	h.etag = `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`

	return h, nil
}

func (h *directoryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hdr := w.Header()
	hdr.Set("Content-Type", MediaTypeDirectory)
	hdr.Set("Cache-Control", "public, max-age="+strconv.Itoa(int(h.maxAge/time.Second)))
	hdr.Set("ETag", h.etag)
	// Appendix C.11: the directory is public, so any origin may read it.
	hdr.Set("Access-Control-Allow-Origin", "*")

	if etagMatches(r.Header.Get("If-None-Match"), h.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	hdr.Set("Content-Digest", h.digest)

	if err := h.sign(hdr, r); err != nil {
		http.Error(w, "can't sign directory", http.StatusInternalServerError)
		return
	}

	hdr.Set("Content-Length", strconv.Itoa(len(h.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(h.body)
	}
}

// sign adds one directory response signature per key to hdr. The signature
// covers the request's authority, so it is computed per request.
func (h *directoryHandler) sign(hdr http.Header, r *http.Request) error {
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     hdr.Clone(),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    r,
	}

	fields := httpsign.NewFields().AddRequestComponent("@authority").AddHeader("content-digest")

	for i, newS := range h.newSigner {
		cfg := httpsign.NewSignConfig().
			SignAlg(false).
			SetTag(TagDirectory).
			SetKeyID(h.keyIDs[i]).
			SetExpiresAfter(int64(h.lifetime / time.Second))

		s, err := newS(cfg, *fields)
		if err != nil {
			return err
		}

		in, sig, err := httpsign.SignResponse("binding"+strconv.Itoa(i), *s, res, r)
		if err != nil {
			return err
		}
		hdr.Add("Signature-Input", in)
		hdr.Add("Signature", sig)
	}

	return nil
}

// etagMatches reports whether an If-None-Match value matches etag.
func etagMatches(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" {
		return false
	}
	for _, v := range strings.Split(ifNoneMatch, ",") {
		v = strings.TrimSpace(v)
		if v == "*" || strings.TrimPrefix(v, "W/") == etag {
			return true
		}
	}
	return false
}
