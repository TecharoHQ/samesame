package samesame

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

func TestGenerateKeyRoundTrip(t *testing.T) {
	t.Parallel()

	for _, alg := range KeyAlgorithms {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()

			key, err := GenerateKey(alg)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if _, gotAlg, err := verifierFunc(key.Public()); err != nil || gotAlg != alg {
				t.Fatalf("generated key verifies %q, want %q (err %v)", gotAlg, alg, err)
			}

			data, err := MarshalPrivateKeyPEM(key)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyPEM: %v", err)
			}
			if !strings.HasPrefix(string(data), "-----BEGIN PRIVATE KEY-----") {
				t.Errorf("not a PKCS #8 PEM block:\n%s", data)
			}

			parsed, err := ParsePrivateKeyPEM(data)
			if err != nil {
				t.Fatalf("ParsePrivateKeyPEM: %v", err)
			}
			if got, want := mustThumbprint(t, parsed.Public()), mustThumbprint(t, key.Public()); got != want {
				t.Errorf("thumbprint changed across PEM round trip: %s != %s", got, want)
			}

			// The parsed key must be usable to sign.
			if _, err := NewSigner(parsed, SignerOptions{AgentOrigin: testAgentOrigin}); err != nil {
				t.Errorf("NewSigner: %v", err)
			}
		})
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	t.Parallel()

	ec := mustGenerate(t, "p256").(*ecdsa.PrivateKey)
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := mustGenerate(t, "rsa").(*rsa.PrivateKey)
	p521, err := x509.MarshalPKCS8PrivateKey(mustGenerate(t, "p521"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name    string
		data    []byte
		wantErr bool
		err     error
	}{
		{name: "RFC 9421 B.1.4 PKCS #8", data: []byte(testEd25519Private)},
		{name: "SEC 1 EC", data: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})},
		{name: "PKCS #1 RSA", data: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})},
		{name: "P-521", data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p521}), wantErr: true, err: ErrUnsupportedKey},
		{name: "public key", data: []byte(testEd25519Public), wantErr: true},
		{name: "not PEM", data: []byte("hello"), wantErr: true},
		{name: "corrupt DER", data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParsePrivateKeyPEM(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("want error=%v, got %v", tt.wantErr, err)
			}
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Errorf("want %v, got %v", tt.err, err)
			}
		})
	}
}

func TestMarshalDirectory(t *testing.T) {
	t.Parallel()

	var keys []crypto.PublicKey
	var ids []string
	for _, alg := range KeyAlgorithms {
		k, err := GenerateKey(alg)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", alg, err)
		}
		// Pass private keys on purpose: only the public halves may appear.
		keys = append(keys, k)
		ids = append(ids, mustThumbprint(t, k.Public()))
	}

	data, err := MarshalDirectory(keys...)
	if err != nil {
		t.Fatalf("MarshalDirectory: %v", err)
	}
	for _, private := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(string(data), private) {
			t.Fatalf("directory contains private member %s:\n%s", private, data)
		}
	}

	dir, err := ParseDirectory(data, DirectoryOptions{})
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(dir.Invalid) != 0 || len(dir.Keys) != len(ids) {
		t.Fatalf("want %d valid keys, got %d: %v", len(ids), len(dir.Keys), dir.Invalid)
	}
	for i, id := range ids {
		if dir.Keys[i].ID != id {
			t.Errorf("key %d: want %s, got %s", i, id, dir.Keys[i].ID)
		}
	}

	if _, err := MarshalDirectory(); err == nil {
		t.Error("empty directory was accepted")
	}
}

func TestGenerateKeyUnsupported(t *testing.T) {
	t.Parallel()

	for _, alg := range []string{"", "hmac-sha256", "rsa-v1_5-sha256", "ed448"} {
		if _, err := GenerateKey(alg); !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("%q: want %v, got %v", alg, ErrUnsupportedKey, err)
		}
	}
}
