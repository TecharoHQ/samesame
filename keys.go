package samesame

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// RSAKeyBits is the modulus size GenerateKey uses for RSA keys.
const RSAKeyBits = 3072

// KeyAlgorithms lists the algorithms GenerateKey accepts.
var KeyAlgorithms = []string{AlgEd25519, AlgECDSAP256SHA256, AlgECDSAP384SHA384, AlgRSAPSSSHA512}

// GenerateKey creates a new signing key for alg, one of KeyAlgorithms.
func GenerateKey(alg string) (crypto.Signer, error) {
	switch alg {
	case AlgEd25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case AlgECDSAP256SHA256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgECDSAP384SHA384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case AlgRSAPSSSHA512:
		return rsa.GenerateKey(rand.Reader, RSAKeyBits)
	default:
		return nil, fmt.Errorf("%w: algorithm %q", ErrUnsupportedKey, alg)
	}
}

// MarshalPrivateKeyPEM encodes key as a PKCS #8 "PRIVATE KEY" PEM block.
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedKey, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM decodes a PEM private key usable by NewSigner and
// NewDirectoryHandler. It accepts PKCS #8 ("PRIVATE KEY"), SEC 1
// ("EC PRIVATE KEY"), and PKCS #1 ("RSA PRIVATE KEY") blocks.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("samesame: no PEM block found")
	}

	var (
		key any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("samesame: unexpected PEM block %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("samesame: can't parse private key: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, key)
	}
	if _, err := signerFunc(signer); err != nil {
		return nil, err
	}
	return signer, nil
}

// PublicJWK returns pub as a JWK ready for a key directory: kid is the key
// thumbprint (protocol draft Section 5.5) and use is "sig". Passing a
// private key is safe; only its public half is exported.
func PublicJWK(pub crypto.PublicKey) (jwk.Key, error) {
	if s, ok := pub.(crypto.Signer); ok {
		pub = s.Public()
	}
	if _, _, err := verifierFunc(pub); err != nil {
		return nil, err
	}

	k, err := jwk.Import[jwk.Key](pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedKey, err)
	}
	id, err := Thumbprint(k)
	if err != nil {
		return nil, err
	}
	if err := k.Set(jwk.KeyIDKey, id); err != nil {
		return nil, fmt.Errorf("samesame: can't set kid: %w", err)
	}
	if err := k.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("samesame: can't set use: %w", err)
	}
	return k, nil
}

// MarshalDirectory serializes the public halves of keys as an HTTP Message
// Signatures Directory, the JSON served at WellKnownPath.
func MarshalDirectory(keys ...crypto.PublicKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("samesame: directory needs at least one key")
	}

	jwks := make([]jwk.Key, 0, len(keys))
	for i, pub := range keys {
		k, err := PublicJWK(pub)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		jwks = append(jwks, k)
	}

	body, err := json.Marshal(struct {
		Keys []jwk.Key `json:"keys"`
	}{jwks})
	if err != nil {
		return nil, fmt.Errorf("samesame: can't serialize directory: %w", err)
	}
	return body, nil
}
