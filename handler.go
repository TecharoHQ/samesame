package samesame

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yaronf/httpsign"
)

const (
	// DefaultDirectoryMaxAge is the default Cache-Control max-age of a served
	// directory.
	DefaultDirectoryMaxAge = time.Hour

	// directorySignatureRefresh is the longest a cached set of directory
	// response signatures is reused before signing again.
	directorySignatureRefresh = time.Hour

	// DefaultDirectorySignatureLifetime is how long directory response
	// signatures stay valid. Appendix C.8 of the protocol draft recommends
	// lifetimes well beyond any republication interval.
	DefaultDirectorySignatureLifetime = 30 * 24 * time.Hour
)

// DirectoryHandlerOptions configures NewDirectoryHandler.
type DirectoryHandlerOptions struct {
	// Authorities lists the hosts, as sent in the Host header and with any
	// non-default port, that this directory is served for, such as
	// "bot.example". Required. Directory response signatures bind the keys
	// to the request's authority (Appendix B.1), so signing for any Host a
	// client sends would hand out proofs for other domains. Requests for
	// other hosts get 421 Misdirected Request.
	Authorities []string

	// MaxAge is sent as Cache-Control max-age. Defaults to
	// DefaultDirectoryMaxAge.
	MaxAge time.Duration

	// SignatureLifetime is the expires - created of each directory response
	// signature. Defaults to DefaultDirectorySignatureLifetime.
	SignatureLifetime time.Duration
}

type directoryHandler struct {
	body        []byte
	digest      string
	etag        string
	maxAge      time.Duration
	lifetime    time.Duration
	refresh     time.Duration
	keyIDs      []string
	newSigner   []newHTTPSigner
	authorities map[string]bool
	now         func() time.Time

	// Signing is the expensive part and the body never changes, so
	// signatures are cached per authority. The map is bounded by the
	// Authorities list.
	mu   sync.Mutex
	sigs map[string]signedHeaders
}

type signedHeaders struct {
	inputs, sigs []string
	until        time.Time
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

	if len(opts.Authorities) == 0 {
		return nil, errors.New("samesame: DirectoryHandlerOptions.Authorities is required")
	}

	h := &directoryHandler{
		maxAge:      opts.MaxAge,
		lifetime:    opts.SignatureLifetime,
		refresh:     min(opts.SignatureLifetime/2, directorySignatureRefresh),
		authorities: make(map[string]bool, len(opts.Authorities)),
		now:         time.Now,
		sigs:        make(map[string]signedHeaders),
	}
	for _, a := range opts.Authorities {
		if a == "" || strings.ContainsAny(a, "/ ") {
			return nil, fmt.Errorf("samesame: invalid authority %q", a)
		}
		h.authorities[strings.ToLower(a)] = true
	}

	pubs := make([]crypto.PublicKey, 0, len(keys))
	for i, key := range keys {
		newS, err := signerFunc(key)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		k, err := PublicJWK(key)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		id, _ := k.KeyID()

		pubs = append(pubs, key.Public())
		h.keyIDs = append(h.keyIDs, id)
		h.newSigner = append(h.newSigner, newS)
	}

	// MarshalDirectory exports only the public halves, so private material
	// can never be served.
	body, err := MarshalDirectory(pubs...)
	if err != nil {
		return nil, err
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

	authority := strings.ToLower(r.Host)
	if !h.authorities[authority] {
		http.Error(w, "this directory is not served for this host", http.StatusMisdirectedRequest)
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

	signed, err := h.signatures(authority, r)
	if err != nil {
		http.Error(w, "can't sign directory", http.StatusInternalServerError)
		return
	}
	hdr["Signature-Input"] = signed.inputs
	hdr["Signature"] = signed.sigs

	hdr.Set("Content-Length", strconv.Itoa(len(h.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(h.body)
	}
}

// signatures returns one directory response signature per key for
// authority, from cache while it is fresh.
func (h *directoryHandler) signatures(authority string, r *http.Request) (signedHeaders, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := h.now()
	if cached, ok := h.sigs[authority]; ok && now.Before(cached.until) {
		return cached, nil
	}

	// Sign for the canonical authority, not whatever case the client used.
	req := r.Clone(r.Context())
	req.Host = authority

	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Digest": {h.digest}},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}

	fields := httpsign.NewFields().AddRequestComponent("@authority").AddHeader("content-digest")

	var signed signedHeaders
	for i, newS := range h.newSigner {
		cfg := httpsign.NewSignConfig().
			SignAlg(false).
			SetTag(TagDirectory).
			SetKeyID(h.keyIDs[i]).
			SetExpiresAfter(int64(h.lifetime / time.Second))

		s, err := newS(cfg, *fields)
		if err != nil {
			return signedHeaders{}, err
		}

		in, sig, err := httpsign.SignResponse("binding"+strconv.Itoa(i), *s, res, req)
		if err != nil {
			return signedHeaders{}, err
		}
		signed.inputs = append(signed.inputs, in)
		signed.sigs = append(signed.sigs, sig)
	}

	signed.until = now.Add(h.refresh)
	h.sigs[authority] = signed
	return signed, nil
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

// StaticDirectory is a key directory with precomputed response signatures,
// for serving from a static file server.
type StaticDirectory struct {
	// Body is the directory JSON, byte for byte what NewDirectoryHandler
	// serves.
	Body []byte

	// Header holds the Content-Type, Cache-Control, Content-Digest,
	// Signature-Input, and Signature fields to send with Body.
	Header http.Header

	// Expires is when the signatures stop being valid. Generate new ones
	// before then.
	Expires time.Time
}

// SignStaticDirectory signs a key directory for one authority, the host
// verifiers fetch it from. The signatures cover only that authority and the
// body's Content-Digest, so they are the same for every request and can be
// configured as static response headers. opts.Authorities is ignored.
//
// The file server must send Body unmodified: compressing it changes the
// bytes Content-Digest covers.
func SignStaticDirectory(keys []crypto.Signer, authority string, opts DirectoryHandlerOptions) (*StaticDirectory, error) {
	if authority != strings.ToLower(authority) {
		return nil, fmt.Errorf("samesame: authority %q must be lowercase", authority)
	}
	opts.Authorities = []string{authority}

	hh, err := NewDirectoryHandler(keys, opts)
	if err != nil {
		return nil, err
	}
	h := hh.(*directoryHandler)

	now := h.now()
	req, err := http.NewRequest(http.MethodGet, "https://"+authority+WellKnownPath, nil)
	if err != nil {
		return nil, fmt.Errorf("samesame: invalid authority %q: %w", authority, err)
	}
	signed, err := h.signatures(authority, req)
	if err != nil {
		return nil, err
	}

	return &StaticDirectory{
		Body: h.body,
		Header: http.Header{
			"Content-Type":    {MediaTypeDirectory},
			"Cache-Control":   {"public, max-age=" + strconv.Itoa(int(h.maxAge/time.Second))},
			"Content-Digest":  {h.digest},
			"Signature-Input": signed.inputs,
			"Signature":       signed.sigs,
		},
		Expires: now.Add(h.lifetime),
	}, nil
}
