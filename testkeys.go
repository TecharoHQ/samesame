package samesame

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// rfc9421TestKeys are the public test keys from RFC 9421 Appendix B.1. The
// Web Bot Auth test vectors use them, so they are widely published. Section
// 6.8 of the protocol draft says verifiers SHOULD reject them.
var rfc9421TestKeys = map[string]string{
	"RFC 9421 B.1.1 test-key-rsa": `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----`,
	"RFC 9421 B.1.2 test-key-rsa-pss": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----`,
	"RFC 9421 B.1.3 test-key-ecc-p256": `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----`,
	"RFC 9421 B.1.4 test-key-ed25519": `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`,
}

// knownTestKeys maps the thumbprint of each RFC 9421 test key to its name.
var knownTestKeys = mustThumbprintTestKeys()

func mustThumbprintTestKeys() map[string]string {
	result := make(map[string]string, len(rfc9421TestKeys))

	for name, data := range rfc9421TestKeys {
		block, _ := pem.Decode([]byte(data))
		if block == nil {
			panic(fmt.Sprintf("samesame: can't decode PEM for %s", name))
		}

		var (
			raw any
			err error
		)
		switch block.Type {
		case "RSA PUBLIC KEY":
			raw, err = x509.ParsePKCS1PublicKey(block.Bytes)
		default:
			raw, err = x509.ParsePKIXPublicKey(block.Bytes)
		}
		if err != nil {
			panic(fmt.Sprintf("samesame: can't parse %s: %v", name, err))
		}

		k, err := jwk.Import[jwk.Key](raw)
		if err != nil {
			panic(fmt.Sprintf("samesame: can't import %s: %v", name, err))
		}

		id, err := Thumbprint(k)
		if err != nil {
			panic(fmt.Sprintf("samesame: can't thumbprint %s: %v", name, err))
		}

		result[id] = name
	}

	return result
}

// IsTestKey reports whether the thumbprint belongs to a published RFC 9421
// test key.
func IsTestKey(thumbprint string) bool {
	_, ok := knownTestKeys[thumbprint]
	return ok
}
