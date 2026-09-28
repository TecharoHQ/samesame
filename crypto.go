package samesame

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"github.com/yaronf/httpsign"
)

// Algorithms this package signs and verifies with, named as in the HTTP
// Signature Algorithms registry. HMAC is deliberately absent: the protocol
// draft (Section 6.4) forbids shared secrets.
const (
	AlgEd25519         = "ed25519"
	AlgECDSAP256SHA256 = "ecdsa-p256-sha256"
	AlgECDSAP384SHA384 = "ecdsa-p384-sha384"
	AlgRSAPSSSHA512    = "rsa-pss-sha512"
)

// MinRSAKeyBits is the smallest RSA modulus accepted for signing or
// verifying.
const MinRSAKeyBits = 2048

func checkRSASize(k *rsa.PublicKey) error {
	if k.N == nil || k.N.BitLen() < MinRSAKeyBits {
		bits := 0
		if k.N != nil {
			bits = k.N.BitLen()
		}
		return fmt.Errorf("%w: %d-bit RSA key, need at least %d", ErrUnsupportedKey, bits, MinRSAKeyBits)
	}
	return nil
}

type (
	newHTTPSigner   func(*httpsign.SignConfig, httpsign.Fields) (*httpsign.Signer, error)
	newHTTPVerifier func(*httpsign.VerifyConfig, httpsign.Fields) (*httpsign.Verifier, error)
)

func signerFunc(key crypto.Signer) (newHTTPSigner, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return func(c *httpsign.SignConfig, f httpsign.Fields) (*httpsign.Signer, error) {
			return httpsign.NewEd25519Signer(k, c, f)
		}, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return func(c *httpsign.SignConfig, f httpsign.Fields) (*httpsign.Signer, error) {
				return httpsign.NewP256Signer(*k, c, f)
			}, nil
		case elliptic.P384():
			return func(c *httpsign.SignConfig, f httpsign.Fields) (*httpsign.Signer, error) {
				return httpsign.NewP384Signer(*k, c, f)
			}, nil
		default:
			return nil, fmt.Errorf("%w: ECDSA curve %s", ErrUnsupportedKey, k.Curve.Params().Name)
		}
	case *rsa.PrivateKey:
		if err := checkRSASize(&k.PublicKey); err != nil {
			return nil, err
		}
		return func(c *httpsign.SignConfig, f httpsign.Fields) (*httpsign.Signer, error) {
			return httpsign.NewRSAPSSSigner(*k, c, f)
		}, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, key)
	}
}

// verifierFunc returns a constructor for an httpsign verifier for pub, and
// the algorithm name that key verifies.
func verifierFunc(pub crypto.PublicKey) (newHTTPVerifier, string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return func(c *httpsign.VerifyConfig, f httpsign.Fields) (*httpsign.Verifier, error) {
			return httpsign.NewEd25519Verifier(k, c, f)
		}, AlgEd25519, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return func(c *httpsign.VerifyConfig, f httpsign.Fields) (*httpsign.Verifier, error) {
				return httpsign.NewP256Verifier(*k, c, f)
			}, AlgECDSAP256SHA256, nil
		case elliptic.P384():
			return func(c *httpsign.VerifyConfig, f httpsign.Fields) (*httpsign.Verifier, error) {
				return httpsign.NewP384Verifier(*k, c, f)
			}, AlgECDSAP384SHA384, nil
		default:
			return nil, "", fmt.Errorf("%w: ECDSA curve %s", ErrUnsupportedKey, k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if err := checkRSASize(k); err != nil {
			return nil, "", err
		}
		return func(c *httpsign.VerifyConfig, f httpsign.Fields) (*httpsign.Verifier, error) {
			return httpsign.NewRSAPSSVerifier(*k, c, f)
		}, AlgRSAPSSSHA512, nil
	default:
		return nil, "", fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
}
