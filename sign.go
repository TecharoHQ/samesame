package samesame

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/yaronf/httpsign"
)

const (
	// DefaultExpiry is how long a signature is valid when SignerOptions.Expiry
	// is zero.
	DefaultExpiry = time.Hour

	// MaxExpiry is the longest signature lifetime the signer allows. The
	// protocol draft (Section 5.2) recommends no more than 24 hours.
	MaxExpiry = 24 * time.Hour

	// DefaultLabel is the default Signature and Signature-Agent member key.
	DefaultLabel = "sig1"

	nonceSize = 64
)

var (
	ErrUnsupportedKey = errors.New("samesame: unsupported signing key")
	ErrSignerConfig   = errors.New("samesame: invalid signer configuration")
	ErrLabelInUse     = errors.New("samesame: signature label already present on request")
)

// SignerOptions configures a Signer.
type SignerOptions struct {
	// AgentOrigin is the https origin that serves this agent's key directory,
	// such as "https://bot.example". It is sent in Signature-Agent. Required:
	// the protocol draft (Section 4.3) says a signed request MUST carry
	// Signature-Agent.
	AgentOrigin string

	// Label is the Signature / Signature-Input dictionary key. Defaults to
	// DefaultLabel.
	Label string

	// AgentKey is the Signature-Agent dictionary key. Defaults to Label.
	AgentKey string

	// Expiry is how long each signature is valid. Defaults to DefaultExpiry
	// and may not exceed MaxExpiry.
	Expiry time.Duration

	// DisableNonce omits the nonce parameter. By default each signature gets
	// a random 64-byte nonce so verifiers can detect replays.
	DisableNonce bool
}

// Signer signs outgoing requests with Web Bot Auth signatures.
type Signer struct {
	opts  SignerOptions
	keyID string
	agent string // serialized Signature-Agent member value
	newHS newHTTPSigner
}

// NewSigner creates a Signer for key, which must be an ed25519.PrivateKey,
// an *ecdsa.PrivateKey on P-256 or P-384, or an *rsa.PrivateKey (signed with
// RSA-PSS SHA-512).
func NewSigner(key crypto.Signer, opts SignerOptions) (*Signer, error) {
	if opts.Label == "" {
		opts.Label = DefaultLabel
	}
	if opts.AgentKey == "" {
		opts.AgentKey = opts.Label
	}
	if opts.Expiry == 0 {
		opts.Expiry = DefaultExpiry
	}

	var errs []error
	if opts.Expiry < time.Second || opts.Expiry > MaxExpiry {
		errs = append(errs, fmt.Errorf("expiry %s must be between 1s and %s", opts.Expiry, MaxExpiry))
	}
	if _, err := directoryIdentifier(opts.AgentOrigin); err != nil {
		errs = append(errs, fmt.Errorf("agent origin: %w", err))
	}
	for name, v := range map[string]string{"label": opts.Label, "agent key": opts.AgentKey} {
		if !isSFKey(v) {
			errs = append(errs, fmt.Errorf("%s %q is not a structured field key", name, v))
		}
	}
	if len(errs) != 0 {
		return nil, fmt.Errorf("%w: %w", ErrSignerConfig, errors.Join(errs...))
	}

	newHS, err := signerFunc(key)
	if err != nil {
		return nil, err
	}

	pub, err := PublicJWK(key)
	if err != nil {
		return nil, err
	}
	keyID, _ := pub.KeyID()

	agent, err := httpsfv.Marshal(httpsfv.NewItem(opts.AgentOrigin))
	if err != nil {
		return nil, fmt.Errorf("%w: can't serialize agent origin: %w", ErrSignerConfig, err)
	}

	return &Signer{opts: opts, keyID: keyID, agent: agent, newHS: newHS}, nil
}

// KeyID returns the thumbprint sent as the keyid parameter.
func (s *Signer) KeyID() string { return s.keyID }

// Sign adds Signature-Agent, Signature-Input, and Signature headers to r. It
// covers @authority and the signer's Signature-Agent member. Existing
// signatures and Signature-Agent members on r are kept. On error, r's headers
// are left as they were.
func (s *Signer) Sign(r *http.Request) error {
	prev := slices.Clone(r.Header.Values(HeaderSignatureAgent))
	if err := s.signRequest(r); err != nil {
		if prev == nil {
			r.Header.Del(HeaderSignatureAgent)
		} else {
			r.Header[http.CanonicalHeaderKey(HeaderSignatureAgent)] = prev
		}
		return err
	}
	return nil
}

func (s *Signer) signRequest(r *http.Request) error {
	if r.Host == "" && r.URL != nil {
		r.Host = r.URL.Host
	}

	for _, h := range []string{"Signature", "Signature-Input"} {
		if hasDictMember(r.Header, h, s.opts.Label) {
			return fmt.Errorf("%w: %s already has %q", ErrLabelInUse, h, s.opts.Label)
		}
	}

	if err := addDictMember(r.Header, HeaderSignatureAgent, s.opts.AgentKey, s.agent); err != nil {
		return err
	}

	cfg := httpsign.NewSignConfig().
		SetTag(TagWebBotAuth).
		SetKeyID(s.keyID).
		SetExpiresAfter(int64(s.opts.Expiry / time.Second))

	if !s.opts.DisableNonce {
		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("samesame: can't generate nonce: %w", err)
		}
		cfg = cfg.SetNonce(base64.RawURLEncoding.EncodeToString(nonce))
	}

	fields := httpsign.NewFields().
		AddHeader("@authority").
		AddDictHeader("signature-agent", s.opts.AgentKey)

	signer, err := s.newHS(cfg, *fields)
	if err != nil {
		return fmt.Errorf("samesame: can't create signer: %w", err)
	}

	sigInput, sig, err := httpsign.SignRequest(s.opts.Label, *signer, r)
	if err != nil {
		return fmt.Errorf("samesame: can't sign request: %w", err)
	}

	r.Header.Add("Signature-Input", sigInput)
	r.Header.Add("Signature", sig)

	return nil
}

// Transport returns an http.RoundTripper that signs every request before
// passing it to next. If next is nil, http.DefaultTransport is used.
func (s *Signer) Transport(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		// A RoundTripper must not modify the caller's request.
		r = r.Clone(r.Context())
		if err := s.Sign(r); err != nil {
			return nil, err
		}
		return next.RoundTrip(r)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// addDictMember adds key=value (value already serialized) to the dictionary
// header name in h. It fails if key is already present with another value.
func addDictMember(h http.Header, name, key, value string) error {
	if values := h.Values(name); len(values) != 0 {
		dict, err := httpsfv.UnmarshalDictionary(values)
		if err != nil {
			return fmt.Errorf("%w: existing %s: %w", ErrMalformedSignatureAgent, name, err)
		}
		if m, ok := dict.Get(key); ok {
			existing, err := httpsfv.Marshal(m)
			if err == nil && existing == value {
				return nil
			}
			return fmt.Errorf("%w: %s already has %q", ErrLabelInUse, name, key)
		}
	}

	h.Add(name, key+"="+value)
	return nil
}

func hasDictMember(h http.Header, name, key string) bool {
	values := h.Values(name)
	if len(values) == 0 {
		return false
	}
	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return false
	}
	_, ok := dict.Get(key)
	return ok
}

// isSFKey reports whether s is a valid structured field dictionary key
// (RFC 9651 Section 3.1.2).
func isSFKey(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case 'a' <= r && r <= 'z', r == '*':
		case i > 0 && ('0' <= r && r <= '9' || r == '_' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	return true
}
