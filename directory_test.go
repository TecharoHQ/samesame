package samesame

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// testEd25519JWK is the RFC 9421 B.1.4 public key as it appears in the
// httpsig-protocol-00 E.2.3 directory.
const testEd25519JWK = `{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}`

// A P-256 key that is not an RFC 9421 test key.
const (
	otherP256JWK = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`
)

func TestThumbprintMatchesSpec(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		jwk  string
		want string
	}{
		{
			name: "RFC 9421 B.1.4 ed25519 (E.2 keyid)",
			jwk:  testEd25519JWK,
			want: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			k, err := jwk.ParseKey([]byte(tt.jwk))
			if err != nil {
				t.Fatalf("can't parse key: %v", err)
			}

			got, err := Thumbprint(k)
			if err != nil {
				t.Fatalf("Thumbprint: %v", err)
			}
			if got != tt.want {
				t.Logf("want: %s", tt.want)
				t.Logf("got:  %s", got)
				t.Error("wrong thumbprint")
			}
		})
	}
}

func TestKnownTestKeys(t *testing.T) {
	t.Parallel()

	if len(knownTestKeys) != len(rfc9421TestKeys) {
		t.Fatalf("want %d test key thumbprints, got %d", len(rfc9421TestKeys), len(knownTestKeys))
	}

	// These keyids are printed in httpsig-protocol-00 Appendix E.
	for _, id := range []string{
		"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U", // E.2, B.1.4
		"oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA", // E.1, B.1.2
	} {
		if !IsTestKey(id) {
			t.Errorf("%s is not recognized as a test key", id)
		}
	}
}

func TestParseDirectory(t *testing.T) {
	t.Parallel()

	manyKeys := "[" + strings.TrimSuffix(strings.Repeat(otherP256JWK+",", DefaultMaxKeys+1), ",") + "]"

	for _, tt := range []struct {
		name        string
		input       string
		opts        DirectoryOptions
		err         error
		wantKeys    int
		wantInvalid int
		wantErrIn   error // expected error inside Directory.Invalid
	}{
		{
			name:     "E.2.3 directory",
			input:    `{"keys":[` + testEd25519JWK + `]}`,
			opts:     DirectoryOptions{AllowTestKeys: true},
			wantKeys: 1,
		},
		{
			name:        "E.2.3 directory rejects test key by default",
			input:       `{"keys":[` + testEd25519JWK + `]}`,
			wantInvalid: 1,
			wantErrIn:   ErrTestKey,
		},
		{
			name:     "key without kid",
			input:    `{"keys":[` + otherP256JWK + `]}`,
			wantKeys: 1,
		},
		{
			// The 5.5.1 example in the draft uses a kid that is not the
			// thumbprint, so it must be dropped.
			name:        "section 5.5.1 example kid is not the thumbprint",
			input:       `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"NFcWBst6DXG-N35nHdzMrioWntdzNZghQSkjHNMMSjw","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig","nbf":1712793600,"exp":1715385600}]}`,
			opts:        DirectoryOptions{AllowTestKeys: true},
			wantInvalid: 1,
			wantErrIn:   ErrInvalidKey,
		},
		{
			name:        "private key material",
			input:       `{"keys":[{"kty":"OKP","crv":"Ed25519","d":"n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}`,
			opts:        DirectoryOptions{AllowTestKeys: true},
			wantInvalid: 1,
			wantErrIn:   ErrInvalidKey,
		},
		{
			name:        "symmetric key",
			input:       `{"keys":[{"kty":"oct","k":"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"}]}`,
			wantInvalid: 1,
			wantErrIn:   ErrInvalidKey,
		},
		{
			name:        "P-521 key",
			input:       `{"keys":[` + jwkJSON(t, mustGenerate(t, "p521").Public()) + `]}`,
			wantInvalid: 1,
			wantErrIn:   ErrUnsupportedKey,
		},
		{
			name:        "1024-bit RSA key",
			input:       `{"keys":[` + rsaPublicJWK(mustGenerateRSA(t, 1024)) + `]}`,
			wantInvalid: 1,
			wantErrIn:   ErrInvalidKey,
		},
		{
			name:     "2048-bit RSA key",
			input:    `{"keys":[` + jwkJSON(t, mustGenerateRSA(t, 2048).Public()) + `]}`,
			wantKeys: 1,
		},
		{
			name:        "private RSA key",
			input:       `{"keys":[` + jwkJSON(t, mustGenerateRSA(t, 2048)) + `]}`,
			wantInvalid: 1,
			wantErrIn:   ErrInvalidKey,
		},
		{
			name:        "encryption key",
			input:       `{"keys":[{"kty":"EC","crv":"P-256","use":"enc","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`,
			wantInvalid: 1,
			wantErrIn:   ErrInvalidKey,
		},
		{
			name:        "one bad key does not drop the good one",
			input:       `{"keys":[{"kty":"nope"},` + otherP256JWK + `]}`,
			wantKeys:    1,
			wantInvalid: 1,
			wantErrIn:   ErrInvalidKey,
		},
		{
			name:  "not JSON",
			input: `{"keys":`,
			err:   ErrMalformedDirectory,
		},
		{
			name:  "no keys array",
			input: `{}`,
			err:   ErrMalformedDirectory,
		},
		{
			name:  "too many keys",
			input: `{"keys":` + manyKeys + `}`,
			err:   ErrTooManyKeys,
		},
		{
			name:     "custom key limit",
			input:    `{"keys":[` + otherP256JWK + `,` + otherP256JWK + `]}`,
			opts:     DirectoryOptions{MaxKeys: 2},
			wantKeys: 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir, err := ParseDirectory([]byte(tt.input), tt.opts)
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Logf("want: %v", tt.err)
					t.Logf("got:  %v", err)
					t.Error("got wrong error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDirectory: %v", err)
			}

			if len(dir.Keys) != tt.wantKeys {
				t.Errorf("want %d keys, got %d", tt.wantKeys, len(dir.Keys))
			}
			if len(dir.Invalid) != tt.wantInvalid {
				t.Errorf("want %d invalid keys, got %d: %v", tt.wantInvalid, len(dir.Invalid), dir.Invalid)
			}
			if tt.wantErrIn != nil {
				found := false
				for _, e := range dir.Invalid {
					if errors.Is(e, tt.wantErrIn) {
						found = true
					}
				}
				if !found {
					t.Errorf("want %v in Invalid, got %v", tt.wantErrIn, dir.Invalid)
				}
			}
		})
	}
}

func TestDirectoryKeyValidity(t *testing.T) {
	t.Parallel()

	nbf := time.Unix(1_000_000, 0)
	exp := time.Unix(2_000_000, 0)
	input := fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","nbf":%d,"exp":%d}]}`, nbf.Unix(), exp.Unix())

	dir, err := ParseDirectory([]byte(input), DirectoryOptions{})
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(dir.Keys) != 1 {
		t.Fatalf("want 1 key, got %d: %v", len(dir.Keys), dir.Invalid)
	}
	id := dir.Keys[0].ID

	for _, tt := range []struct {
		name string
		id   string
		now  time.Time
		want bool
	}{
		{name: "before nbf", id: id, now: nbf.Add(-time.Second), want: false},
		{name: "at nbf", id: id, now: nbf, want: true},
		{name: "inside window", id: id, now: nbf.Add(time.Hour), want: true},
		{name: "at exp", id: id, now: exp, want: false},
		{name: "unknown id", id: "nope", now: nbf.Add(time.Hour), want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, ok := dir.Key(tt.id, tt.now)
			if ok != tt.want {
				t.Errorf("want %v, got %v", tt.want, ok)
			}
		})
	}
}

// jwkJSON serializes a raw key as a JWK.
func jwkJSON(t *testing.T, raw any) string {
	t.Helper()

	k, err := jwk.Import[jwk.Key](raw)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(data)
}

// rsaPublicJWK serializes an RSA public key by hand, because jwx refuses to
// import keys under 2048 bits.
func rsaPublicJWK(k *rsa.PrivateKey) string {
	b64 := base64.RawURLEncoding.EncodeToString
	return fmt.Sprintf(`{"kty":"RSA","n":"%s","e":"%s"}`,
		b64(k.N.Bytes()), b64(big.NewInt(int64(k.E)).Bytes()))
}

func mustGenerateRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()

	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func TestNewKey(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		key  func(t *testing.T) jwk.Key
		err  error
	}{
		{
			name: "ed25519 public",
			key: func(t *testing.T) jwk.Key {
				k, _ := jwk.ParseKey([]byte(testEd25519JWK))
				return k
			},
		},
		{
			name: "ed25519 private",
			key: func(t *testing.T) jwk.Key {
				k, err := jwk.Import[jwk.Key](mustGenerate(t, "ed25519"))
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			err: ErrInvalidKey,
		},
		{
			name: "nil",
			key:  func(t *testing.T) jwk.Key { return nil },
			err:  ErrInvalidKey,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			k, err := NewKey(tt.key(t))
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Errorf("want %v, got %v", tt.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewKey: %v", err)
			}
			if k.newVerifier == nil || k.alg == "" {
				t.Error("NewKey did not cache the verifier")
			}
		})
	}
}
