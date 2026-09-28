package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TecharoHQ/samesame"
)

// run executes the CLI with args and returns its standard output.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	err := newApp(&stdout, &stderr).Run(context.Background(), append([]string{"samesame"}, args...))
	return stdout.String(), err
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()

	out, err := run(t, args...)
	if err != nil {
		t.Fatalf("samesame %s: %v", strings.Join(args, " "), err)
	}
	return out
}

func TestKeygen(t *testing.T) {
	t.Parallel()

	for _, alg := range samesame.KeyAlgorithms {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "key.pem")
			keyID := strings.TrimSpace(mustRun(t, "keygen", "--alg", alg, "--out", path))

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("private key mode: want 0600, got %o", mode)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			key, err := samesame.ParsePrivateKeyPEM(data)
			if err != nil {
				t.Fatalf("ParsePrivateKeyPEM: %v", err)
			}

			// The printed keyid is the key's thumbprint, and the key signs
			// requests whose keyid matches.
			s, err := samesame.NewSigner(key, samesame.SignerOptions{AgentOrigin: "https://bot.test"})
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			if s.KeyID() != keyID {
				t.Errorf("printed keyid %s, signer uses %s", keyID, s.KeyID())
			}

			if got := strings.TrimSpace(mustRun(t, "keyid", path)); got != keyID {
				t.Errorf("keyid command: want %s, got %s", keyID, got)
			}
		})
	}
}

func TestKeygenRefusesOverwrite(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := run(t, "keygen", "--out", path); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want an error mentioning --force, got %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "precious" {
		t.Fatal("existing file was modified")
	}

	mustRun(t, "keygen", "--out", path, "--force")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("--force left mode %o, want 0600", mode)
	}
}

func TestKeygenErrors(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		args []string
	}{
		{name: "missing --out", args: []string{"keygen"}},
		{name: "unsupported algorithm", args: []string{"keygen", "--alg", "hmac-sha256", "--out", filepath.Join(t.TempDir(), "k")}},
		{name: "directory without keys", args: []string{"directory"}},
		{name: "directory with missing file", args: []string{"directory", filepath.Join(t.TempDir(), "nope.pem")}},
		{name: "keyid without keys", args: []string{"keyid"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := run(t, tt.args...); err == nil {
				t.Error("want an error, got none")
			}
		})
	}
}

func TestDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	current, next := filepath.Join(dir, "current.pem"), filepath.Join(dir, "next.pem")
	currentID := strings.TrimSpace(mustRun(t, "keygen", "--out", current))
	nextID := strings.TrimSpace(mustRun(t, "keygen", "--alg", samesame.AlgECDSAP256SHA256, "--out", next))

	// A public key PEM works too.
	pubPath := filepath.Join(dir, "current.pub")
	writePublicPEM(t, current, pubPath)

	for _, tt := range []struct {
		name    string
		args    []string
		wantIDs []string
	}{
		{name: "one key", args: []string{"directory", current}, wantIDs: []string{currentID}},
		{name: "rotation", args: []string{"directory", current, next}, wantIDs: []string{currentID, nextID}},
		{name: "public key file", args: []string{"directory", pubPath}, wantIDs: []string{currentID}},
		{name: "pretty", args: []string{"directory", "--pretty", current}, wantIDs: []string{currentID}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := mustRun(t, tt.args...)
			if strings.Contains(out, `"d"`) {
				t.Fatalf("directory leaks private key material:\n%s", out)
			}

			parsed, err := samesame.ParseDirectory([]byte(out), samesame.DirectoryOptions{})
			if err != nil {
				t.Fatalf("ParseDirectory: %v\n%s", err, out)
			}
			if len(parsed.Invalid) != 0 || len(parsed.Keys) != len(tt.wantIDs) {
				t.Fatalf("want %d valid keys, got %d: %v", len(tt.wantIDs), len(parsed.Keys), parsed.Invalid)
			}
			for i, id := range tt.wantIDs {
				if parsed.Keys[i].ID != id {
					t.Errorf("key %d: want %s, got %s", i, id, parsed.Keys[i].ID)
				}
			}
		})
	}

	t.Run("matches what the handler serves", func(t *testing.T) {
		t.Parallel()

		data, err := os.ReadFile(current)
		if err != nil {
			t.Fatal(err)
		}
		key, err := samesame.ParsePrivateKeyPEM(data)
		if err != nil {
			t.Fatal(err)
		}
		want, err := samesame.MarshalDirectory(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(mustRun(t, "directory", current)); got != string(want) {
			t.Errorf("want %s, got %s", want, got)
		}
	})

	t.Run("write to file", func(t *testing.T) {
		t.Parallel()

		out := filepath.Join(t.TempDir(), "directory.json")
		if stdout := mustRun(t, "directory", "--out", out, current); stdout != "" {
			t.Errorf("unexpected output %q", stdout)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := samesame.ParseDirectory(data, samesame.DirectoryOptions{}); err != nil {
			t.Errorf("ParseDirectory: %v", err)
		}
	})
}

func TestKeyIDMultiple(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.pem"), filepath.Join(dir, "b.pem")
	aID := strings.TrimSpace(mustRun(t, "keygen", "--out", a))
	bID := strings.TrimSpace(mustRun(t, "keygen", "--out", b))

	want := aID + "\t" + a + "\n" + bID + "\t" + b + "\n"
	if got := mustRun(t, "keyid", a, b); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// The RFC 9421 B.1.4 test key has a keyid printed in the protocol draft.
func TestKeyIDMatchesSpec(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "test-key-ed25519.pem")
	keyPEM := "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := strings.TrimSpace(mustRun(t, "keyid", path)); got != "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U" {
		t.Errorf("got %s", got)
	}
}

// writePublicPEM writes the public half of the private key at src as a
// PKIX "PUBLIC KEY" PEM file at dst.
func writePublicPEM(t *testing.T, src, dst string) {
	t.Helper()

	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	key, err := samesame.ParsePrivateKeyPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPublicKeyFormats(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	priv := filepath.Join(dir, "rsa.pem")
	keyID := strings.TrimSpace(mustRun(t, "keygen", "--alg", samesame.AlgRSAPSSSHA512, "--out", priv))

	data, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := samesame.ParsePrivateKeyPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub := key.Public().(*rsa.PublicKey)
	pkix, err := x509.MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name  string
		block *pem.Block
	}{
		{name: "PKIX PUBLIC KEY", block: &pem.Block{Type: "PUBLIC KEY", Bytes: pkix}},
		{name: "PKCS #1 RSA PUBLIC KEY", block: &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "pub.pem")
			if err := os.WriteFile(path, pem.EncodeToMemory(tt.block), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(mustRun(t, "keyid", path)); got != keyID {
				t.Errorf("want %s, got %s", keyID, got)
			}
		})
	}
}

func TestDirectorySignFor(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	key := filepath.Join(dir, "bot.key")
	keyID := strings.TrimSpace(mustRun(t, "keygen", "--out", key))

	for _, tt := range []struct {
		name        string
		format      string
		wantNginx   bool
		wantCaddy   bool
		extraArgs   []string
		wantMaxAge  string
		wantExpires time.Duration
	}{
		{name: "both", format: "both", wantNginx: true, wantCaddy: true, wantMaxAge: "max-age=3600", wantExpires: samesame.DefaultDirectorySignatureLifetime},
		{name: "nginx", format: "nginx", wantNginx: true, wantMaxAge: "max-age=3600", wantExpires: samesame.DefaultDirectorySignatureLifetime},
		{
			name: "caddy with custom lifetimes", format: "caddy", wantCaddy: true,
			extraArgs: []string{"--lifetime", "2160h", "--max-age", "10m"}, wantMaxAge: "max-age=600", wantExpires: 2160 * time.Hour,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := filepath.Join(t.TempDir(), "http-message-signatures-directory")
			args := append([]string{"directory", key, "--sign-for", "Bot.Example", "--format", tt.format, "--out", out}, tt.extraArgs...)
			conf := mustRun(t, args...)

			// The body is written exactly, with no trailing newline, since
			// Content-Digest covers these bytes.
			body, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(key)
			if err != nil {
				t.Fatal(err)
			}
			priv, err := samesame.ParsePrivateKeyPEM(data)
			if err != nil {
				t.Fatal(err)
			}
			want, err := samesame.MarshalDirectory(priv.Public())
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != string(want) {
				t.Errorf("body is not byte for byte the directory:\n%q\n%q", body, want)
			}

			sum := sha256.Sum256(body)
			digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"

			if got := strings.Contains(conf, "location = "+samesame.WellKnownPath); got != tt.wantNginx {
				t.Errorf("nginx block present = %v, want %v", got, tt.wantNginx)
			}
			if got := strings.Contains(conf, "handle "+samesame.WellKnownPath); got != tt.wantCaddy {
				t.Errorf("caddy block present = %v, want %v", got, tt.wantCaddy)
			}

			for _, want := range []string{
				digest,
				`keyid="` + keyID + `"`,
				`("@authority";req "content-digest")`,
				`tag="http-message-signatures-directory"`,
				tt.wantMaxAge,
				samesame.MediaTypeDirectory,
				// Hosts are lowercased: the signature binds the canonical
				// authority.
				"block for bot.example.",
			} {
				if !strings.Contains(conf, want) {
					t.Errorf("config is missing %q:\n%s", want, conf)
				}
			}
			if tt.wantNginx && (!strings.Contains(conf, "gzip off;") || !strings.Contains(conf, "alias "+out+";")) {
				t.Errorf("nginx block must disable gzip and alias the file:\n%s", conf)
			}
			if tt.wantCaddy && !strings.Contains(conf, "encode @compress") {
				t.Errorf("caddy block must explain excluding the path from encode:\n%s", conf)
			}

			// The expiry comment reflects --lifetime.
			wantExp := time.Now().Add(tt.wantExpires).UTC().Format("2006-01-02")
			if !strings.Contains(conf, "expire at "+wantExp) {
				t.Errorf("config does not say the signatures expire on %s:\n%s", wantExp, conf)
			}
		})
	}
}

func TestDirectorySignForErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	key := filepath.Join(dir, "bot.key")
	mustRun(t, "keygen", "--out", key)
	pub := filepath.Join(dir, "bot.pub")
	writePublicPEM(t, key, pub)
	out := filepath.Join(dir, "out")

	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{name: "no --out", args: []string{"directory", key, "--sign-for", "bot.example"}, want: "--out"},
		{name: "--pretty", args: []string{"directory", key, "--sign-for", "bot.example", "--out", out, "--pretty"}, want: "--pretty"},
		{name: "public key", args: []string{"directory", pub, "--sign-for", "bot.example", "--out", out}, want: "private key"},
		{name: "unknown format", args: []string{"directory", key, "--sign-for", "bot.example", "--out", out, "--format", "apache"}, want: "unknown format"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := run(t, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("want an error mentioning %q, got %v", tt.want, err)
			}
		})
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a failed run wrote the output file")
	}
}
