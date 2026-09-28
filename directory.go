package samesame

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// DefaultMaxKeys is the default cap on the number of keys in a directory.
const DefaultMaxKeys = 32

var (
	ErrMalformedDirectory = errors.New("samesame: malformed key directory")
	ErrTooManyKeys        = errors.New("samesame: key directory has too many keys")
	ErrInvalidKey         = errors.New("samesame: invalid key in directory")
	ErrTestKey            = errors.New("samesame: key is a published test key")
)

// Key is a public key from a key directory.
type Key struct {
	// ID is the base64url JWK SHA-256 thumbprint (RFC 7638, RFC 8037). A
	// signature's keyid parameter must match it.
	ID string

	// JWK is the public key.
	JWK jwk.Key

	// NotBefore and Expires come from the nbf and exp members, and are zero
	// when absent. The protocol draft does not define these members, so
	// honoring them is local policy.
	NotBefore time.Time
	Expires   time.Time
}

// ValidAt reports whether the key's nbf/exp window contains t.
func (k Key) ValidAt(t time.Time) bool {
	if !k.NotBefore.IsZero() && t.Before(k.NotBefore) {
		return false
	}
	if !k.Expires.IsZero() && !t.Before(k.Expires) {
		return false
	}
	return true
}

// DirectoryOptions controls how a key directory is parsed.
type DirectoryOptions struct {
	// MaxKeys caps the number of keys a directory may list (protocol draft
	// Section 6.7). Zero means DefaultMaxKeys.
	MaxKeys int

	// AllowTestKeys accepts the published RFC 9421 test keys. Only tests
	// should set this (protocol draft Section 6.8).
	AllowTestKeys bool
}

// Directory is a parsed HTTP Message Signatures Directory.
type Directory struct {
	Keys []Key

	// Invalid holds one error per key that was dropped while parsing. The
	// protocol draft says verifiers should reject malformed entries, so one
	// bad key does not reject the whole directory.
	Invalid []error
}

// ParseDirectory parses a JWKS key directory. It fails only when the document
// as a whole is malformed or too large; bad individual keys are dropped and
// recorded in Directory.Invalid.
func ParseDirectory(data []byte, opts DirectoryOptions) (*Directory, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedDirectory, err)
	}
	if doc.Keys == nil {
		return nil, fmt.Errorf("%w: no keys array", ErrMalformedDirectory)
	}

	maxKeys := opts.MaxKeys
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	if len(doc.Keys) > maxKeys {
		return nil, fmt.Errorf("%w: %d keys, limit is %d", ErrTooManyKeys, len(doc.Keys), maxKeys)
	}

	var result Directory
	for i, raw := range doc.Keys {
		key, err := parseDirectoryKey(raw, opts)
		if err != nil {
			result.Invalid = append(result.Invalid, fmt.Errorf("key %d: %w", i, err))
			continue
		}
		result.Keys = append(result.Keys, key)
	}

	return &result, nil
}

func parseDirectoryKey(raw json.RawMessage, opts DirectoryOptions) (Key, error) {
	var meta struct {
		Kid *string  `json:"kid"`
		Use *string  `json:"use"`
		D   *string  `json:"d"`
		NBF *float64 `json:"nbf"`
		EXP *float64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return Key{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	if meta.D != nil {
		return Key{}, fmt.Errorf("%w: contains private key material", ErrInvalidKey)
	}
	if meta.Use != nil && *meta.Use != string(jwk.ForSignature) {
		return Key{}, fmt.Errorf("%w: use is %q, not %q", ErrInvalidKey, *meta.Use, jwk.ForSignature)
	}

	k, err := jwk.ParseKey(raw)
	if err != nil {
		return Key{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	if err := k.Validate(); err != nil {
		return Key{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	id, err := Thumbprint(k)
	if err != nil {
		return Key{}, err
	}

	// Protocol draft Section 5.5: a kid in a well-known directory MUST be the
	// thumbprint.
	if meta.Kid != nil && *meta.Kid != id {
		return Key{}, fmt.Errorf("%w: kid %q is not the key thumbprint %q", ErrInvalidKey, *meta.Kid, id)
	}

	if !opts.AllowTestKeys && IsTestKey(id) {
		return Key{}, fmt.Errorf("%w: %s", ErrTestKey, knownTestKeys[id])
	}

	result := Key{ID: id, JWK: k}
	if meta.NBF != nil {
		result.NotBefore = time.Unix(int64(*meta.NBF), 0)
	}
	if meta.EXP != nil {
		result.Expires = time.Unix(int64(*meta.EXP), 0)
	}

	return result, nil
}

// Thumbprint returns the base64url JWK SHA-256 thumbprint of k. Web Bot Auth
// uses this as the keyid signature parameter.
func Thumbprint(k jwk.Key) (string, error) {
	sum, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: can't compute thumbprint: %w", ErrInvalidKey, err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// Key returns the key with the given thumbprint if it is valid at now.
func (d *Directory) Key(id string, now time.Time) (Key, bool) {
	for _, k := range d.Keys {
		if k.ID == id && k.ValidAt(now) {
			return k, true
		}
	}
	return Key{}, false
}
