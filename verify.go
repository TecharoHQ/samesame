package samesame

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/yaronf/httpsign"
)

const (
	// DefaultMaxValidity is the default longest expires - created window the
	// verifier accepts. The protocol draft recommends signers stay within 24
	// hours (Section 5.2) and leaves the verifier's limit to policy
	// (Appendix C.6).
	DefaultMaxValidity = 24 * time.Hour

	// DefaultClockSkew is the default tolerance for created and expires.
	DefaultClockSkew = time.Minute

	// DefaultMaxSignatures is the default number of web-bot-auth signatures
	// the verifier will look at in one request.
	DefaultMaxSignatures = 4
)

// KeyResolver resolves a Signature-Agent identifier to its key directory.
// Fetcher implements it.
type KeyResolver interface {
	Resolve(ctx context.Context, identifier *url.URL) (*Directory, error)
}

// VerifierOptions configures a Verifier.
type VerifierOptions struct {
	// Resolver fetches key directories named by Signature-Agent. When nil,
	// only StaticKeys are used.
	Resolver KeyResolver

	// StaticKeys are keys known out of band. A request verified with one of
	// them is identified only by its key thumbprint, never by a URL
	// (protocol draft Section 4.3).
	StaticKeys []crypto.PublicKey

	// AllowTestKeys accepts the published RFC 9421 test keys in StaticKeys.
	// Only tests should set this.
	AllowTestKeys bool

	// MaxValidity caps expires - created. Zero means DefaultMaxValidity.
	MaxValidity time.Duration

	// ClockSkew is the tolerance applied to created and expires. Zero means
	// DefaultClockSkew.
	ClockSkew time.Duration

	// MaxSignatures caps how many web-bot-auth signatures in one request are
	// examined. Zero means DefaultMaxSignatures.
	MaxSignatures int

	// NonceStore, when set, rejects signatures whose nonce was already seen.
	NonceStore NonceStore

	// RequireNonce rejects signatures without a nonce. It only makes sense
	// with a NonceStore.
	RequireNonce bool

	// Scheme returns the scheme the client used. Behind a reverse proxy that
	// terminates TLS, set this to read a trusted forwarded header. The
	// default is "https" when r.TLS is set and "http" otherwise.
	Scheme func(r *http.Request) string

	// AllowInsecure accepts signatures on plaintext HTTP requests. The
	// protocol draft (Section 6.1) says origins SHOULD refuse them.
	AllowInsecure bool

	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

// Result describes a verified signature.
type Result struct {
	Outcome Outcome

	// Label is the signature's label in Signature and Signature-Input.
	Label string

	// KeyID is the key thumbprint. When Identifier is nil, it is the only
	// identity the request has.
	KeyID string

	// Identifier is the resolved key directory URL the request is attributed
	// to, or nil when the key came from StaticKeys.
	Identifier *url.URL

	// Key is the public key the signature verified with.
	Key jwk.Key

	Created time.Time
	Expires time.Time
	Nonce   string

	// NonceChecked is true when a NonceStore saw this nonce for the first
	// time. It is false when there was no nonce or no NonceStore.
	NonceChecked bool
}

// Verifier checks web-bot-auth signatures on incoming requests.
type Verifier struct {
	opts   VerifierOptions
	static map[string]Key
}

// NewVerifier creates a Verifier.
func NewVerifier(opts VerifierOptions) (*Verifier, error) {
	if opts.MaxValidity <= 0 {
		opts.MaxValidity = DefaultMaxValidity
	}
	if opts.ClockSkew <= 0 {
		opts.ClockSkew = DefaultClockSkew
	}
	if opts.MaxSignatures <= 0 {
		opts.MaxSignatures = DefaultMaxSignatures
	}
	if opts.Scheme == nil {
		opts.Scheme = func(r *http.Request) string {
			if r.TLS != nil {
				return "https"
			}
			return "http"
		}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.RequireNonce && opts.NonceStore == nil {
		return nil, errors.New("samesame: RequireNonce needs a NonceStore")
	}

	static := make(map[string]Key, len(opts.StaticKeys))
	for i, pub := range opts.StaticKeys {
		k, err := jwk.Import[jwk.Key](pub)
		if err != nil {
			return nil, fmt.Errorf("%w: static key %d: %w", ErrUnsupportedKey, i, err)
		}
		key, err := NewKey(k)
		if err != nil {
			return nil, fmt.Errorf("static key %d: %w", i, err)
		}
		if !opts.AllowTestKeys && IsTestKey(key.ID) {
			return nil, fmt.Errorf("static key %d: %w: %s", i, ErrTestKey, knownTestKeys[key.ID])
		}
		static[key.ID] = key
	}

	return &Verifier{opts: opts, static: static}, nil
}

// Verify checks the web-bot-auth signatures on r. It returns the first
// signature that verifies. Otherwise it returns a *VerifyError: if any
// signature is invalid the error's outcome is OutcomeInvalid, else it is
// OutcomeUnverified.
func (v *Verifier) Verify(r *http.Request) (*Result, error) {
	if len(r.Header.Values("Signature-Input")) == 0 && len(r.Header.Values("Signature")) == 0 {
		return nil, unverified("", ErrNoSignature)
	}

	if !v.opts.AllowInsecure && v.opts.Scheme(r) != "https" {
		return nil, invalid("", ErrInsecureTransport)
	}

	sigInputs, err := httpsfv.UnmarshalDictionary(r.Header.Values("Signature-Input"))
	if err != nil {
		return nil, invalid("", fmt.Errorf("%w: Signature-Input: %w", ErrMalformedSignature, err))
	}

	all, err := httpsign.RequestDetailsListByTag(r, TagWebBotAuth)
	if err != nil {
		return nil, invalid("", fmt.Errorf("%w: %w", ErrMalformedSignature, err))
	}
	if len(all) == 0 {
		return nil, unverified("", ErrNoSignature)
	}
	if len(all) > v.opts.MaxSignatures {
		return nil, invalid("", fmt.Errorf("%w: %d, limit is %d", ErrTooManySignatures, len(all), v.opts.MaxSignatures))
	}

	agent, err := ParseSignatureAgent(r.Header)
	if err != nil {
		return nil, invalid("", err)
	}

	// Protocol draft Section 5.2.2: verify each signature independently.
	var firstInvalid, firstUnverified *VerifyError
	for _, details := range all {
		res, verr := v.verifyOne(r, sigInputs, agent, details)
		if verr == nil {
			return res, nil
		}
		switch {
		case verr.Outcome == OutcomeInvalid && firstInvalid == nil:
			firstInvalid = verr
		case verr.Outcome == OutcomeUnverified && firstUnverified == nil:
			firstUnverified = verr
		}
	}

	if firstInvalid != nil {
		return nil, firstInvalid
	}
	return nil, firstUnverified
}

// covered is what verifyOne needs to know about a signature's covered
// components, read from Signature-Input.
type covered struct {
	authority, targetURI bool
	agentCovered         bool
	agentKey             string // ;key= of the signature-agent component, "" if unkeyed
}

func coveredComponents(sigInputs *httpsfv.Dictionary, label string) (covered, error) {
	var c covered

	m, ok := sigInputs.Get(label)
	if !ok {
		return c, fmt.Errorf("%w: no Signature-Input for %q", ErrMalformedSignature, label)
	}
	list, ok := m.(httpsfv.InnerList)
	if !ok {
		return c, fmt.Errorf("%w: Signature-Input %q is not an inner list", ErrMalformedSignature, label)
	}

	for _, item := range list.Items {
		name, ok := item.Value.(string)
		if !ok {
			return c, fmt.Errorf("%w: component is not a string", ErrMalformedSignature)
		}

		switch name {
		case "@authority":
			c.authority = true
		case "@target-uri":
			c.targetURI = true
		case "signature-agent":
			if c.agentCovered {
				// Covering two members makes attribution ambiguous.
				return c, fmt.Errorf("%w: signature-agent covered more than once", ErrProfile)
			}
			c.agentCovered = true
			if k, ok := item.Params.Get("key"); ok {
				s, ok := k.(string)
				if !ok {
					return c, fmt.Errorf("%w: signature-agent key is not a string", ErrMalformedSignature)
				}
				c.agentKey = s
			}
		}
	}

	return c, nil
}

func (v *Verifier) verifyOne(r *http.Request, sigInputs *httpsfv.Dictionary, agent *SignatureAgent, d *httpsign.MessageDetails) (*Result, *VerifyError) {
	label := d.Label
	now := v.opts.Now()

	// Protocol draft Section 5.2: created, expires, and keyid are required,
	// and at least one of @authority or @target-uri must be covered.
	if d.KeyID == nil || *d.KeyID == "" {
		return nil, invalid(label, fmt.Errorf("%w: no keyid", ErrProfile))
	}
	if d.Created == nil || d.Expires == nil {
		return nil, invalid(label, fmt.Errorf("%w: created and expires are required", ErrProfile))
	}
	keyID := *d.KeyID

	cov, err := coveredComponents(sigInputs, label)
	if err != nil {
		return nil, invalid(label, err)
	}
	if !cov.authority && !cov.targetURI {
		return nil, invalid(label, fmt.Errorf("%w: neither @authority nor @target-uri is covered", ErrProfile))
	}

	switch {
	case d.Created.After(now.Add(v.opts.ClockSkew)):
		return nil, invalid(label, fmt.Errorf("%w: created %s", ErrNotYetValid, d.Created.UTC()))
	case !d.Expires.After(now.Add(-v.opts.ClockSkew)):
		return nil, invalid(label, fmt.Errorf("%w: expired %s", ErrExpired, d.Expires.UTC()))
	case !d.Expires.After(*d.Created):
		return nil, invalid(label, fmt.Errorf("%w: expires is not after created", ErrProfile))
	case d.Expires.Sub(*d.Created) > v.opts.MaxValidity:
		return nil, invalid(label, fmt.Errorf("%w: %s, limit is %s", ErrValidityTooLong, d.Expires.Sub(*d.Created), v.opts.MaxValidity))
	}

	// Find the Signature-Agent member this signature covers. It is located
	// by the component's ;key=, never by the signature label (protocol
	// draft Section 6.6.1).
	var member *AgentMember
	if cov.agentCovered {
		m, ok := agent.Member(cov.agentKey)
		if !ok {
			return nil, invalid(label, fmt.Errorf("%w: covered Signature-Agent member %q is missing", ErrProfile, cov.agentKey))
		}
		member = &m
	}

	key, identifier, verr := v.resolveKey(r.Context(), label, keyID, member, now)
	if verr != nil {
		return nil, verr
	}

	if key.newVerifier == nil {
		// Built by hand rather than with NewKey, e.g. by a custom
		// KeyResolver.
		k, err := NewKey(key.JWK)
		if err != nil {
			return nil, unverified(label, fmt.Errorf("%w: %w", ErrKeyUnknown, err))
		}
		key.newVerifier, key.alg = k.newVerifier, k.alg
	}
	newV, alg := key.newVerifier, key.alg

	fields := httpsign.NewFields()
	if cov.authority {
		fields.AddHeader("@authority")
	}
	if cov.targetURI {
		fields.AddHeader("@target-uri")
	}
	switch {
	case member != nil && agent.Legacy:
		fields.AddHeader("signature-agent")
	case member != nil:
		fields.AddDictHeader("signature-agent", cov.agentKey)
	}

	cfg := httpsign.NewVerifyConfig().
		SetVerifyCreated(false).
		SetRejectExpired(false).
		SetAllowedTags([]string{TagWebBotAuth}).
		// Defense in depth: the resolved key already fixes the algorithm, so
		// a mismatched alg parameter could not verify anyway.
		SetAllowedAlgs([]string{alg}).
		SetKeyID(keyID).
		SetSchemeFromRequest(v.opts.Scheme)

	hv, err := newV(cfg, *fields)
	if err != nil {
		return nil, unverified(label, fmt.Errorf("samesame: can't create verifier: %w", err))
	}
	if err := httpsign.VerifyRequest(label, *hv, r); err != nil {
		return nil, invalid(label, fmt.Errorf("%w: %w", ErrBadSignature, err))
	}

	// Only record nonces of signatures that verified, so a forger cannot
	// burn a legitimate agent's nonce.
	var (
		nonce        string
		nonceChecked bool
	)
	if d.Nonce != nil {
		nonce = *d.Nonce
	}
	switch {
	case nonce == "" && v.opts.RequireNonce:
		return nil, invalid(label, ErrNonceRequired)
	case nonce != "" && v.opts.NonceStore != nil:
		scope := "keyid:" + keyID
		if identifier != nil {
			scope = identifier.String()
		}
		fresh, err := v.opts.NonceStore.CheckAndRecord(r.Context(), scope, nonce, d.Expires.Add(v.opts.ClockSkew))
		if err != nil {
			return nil, unverified(label, fmt.Errorf("%w: %w", ErrNonceStore, err))
		}
		if !fresh {
			return nil, invalid(label, ErrReplay)
		}
		nonceChecked = true
	}

	return &Result{
		Outcome:      OutcomeVerified,
		Label:        label,
		KeyID:        keyID,
		Identifier:   identifier,
		Key:          key.JWK,
		Created:      *d.Created,
		Expires:      *d.Expires,
		Nonce:        nonce,
		NonceChecked: nonceChecked,
	}, nil
}

// resolveKey finds the key for keyID. A key from the covered member's
// directory attributes the request to that directory's identifier. Otherwise
// a static key may verify it, identified only by thumbprint (protocol draft
// Sections 4.3 and 6.10).
func (v *Verifier) resolveKey(ctx context.Context, label, keyID string, member *AgentMember, now time.Time) (Key, *url.URL, *VerifyError) {
	why := fmt.Errorf("%w: no Signature-Agent covered and keyid %q is not a static key", ErrKeyUnknown, keyID)

	switch {
	case member == nil:
	case member.Identifier == nil:
		why = fmt.Errorf("%w: Signature-Agent member ignored: %w", ErrKeyUnknown, member.Err)
	case v.opts.Resolver == nil:
		why = fmt.Errorf("%w: no resolver for %s", ErrKeyUnknown, member.Identifier)
	default:
		dir, err := v.opts.Resolver.Resolve(ctx, member.Identifier)
		if err != nil {
			why = fmt.Errorf("%w: %s: %w", ErrDiscovery, member.Identifier, err)
			break
		}
		if k, ok := dir.Key(keyID, now); ok {
			return k, member.Identifier, nil
		}
		why = fmt.Errorf("%w: %s has no valid key %q", ErrKeyUnknown, member.Identifier, keyID)
	}

	if k, ok := v.static[keyID]; ok {
		return k, nil, nil
	}
	return Key{}, nil, unverified(label, why)
}
