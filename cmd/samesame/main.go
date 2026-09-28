// Command samesame generates and inspects Web Bot Auth signing keys.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/TecharoHQ/samesame"
	"github.com/urfave/cli/v3"
)

func main() {
	if err := newApp(os.Stdout, os.Stderr).Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "samesame:", err)
		os.Exit(1)
	}
}

func newApp(stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:      "samesame",
		Usage:     "generate and inspect Web Bot Auth signing keys",
		Writer:    stdout,
		ErrWriter: stderr,
		Commands: []*cli.Command{
			keygenCommand(),
			directoryCommand(),
			keyIDCommand(),
		},
	}
}

func keygenCommand() *cli.Command {
	return &cli.Command{
		Name:  "keygen",
		Usage: "generate a private signing key and print its keyid",
		Description: "Writes a new PKCS #8 PEM private key with mode 0600 and prints the key's\n" +
			"thumbprint, which is the keyid its signatures carry.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "alg",
				Aliases: []string{"a"},
				Value:   samesame.AlgEd25519,
				Usage:   "signature algorithm: " + strings.Join(samesame.KeyAlgorithms, ", "),
				Validator: func(alg string) error {
					if !slices.Contains(samesame.KeyAlgorithms, alg) {
						return fmt.Errorf("unsupported algorithm %q, use one of: %s", alg, strings.Join(samesame.KeyAlgorithms, ", "))
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:     "out",
				Aliases:  []string{"o"},
				Usage:    "file to write the private key to",
				Required: true,
			},
			&cli.BoolFlag{
				Name:  "force",
				Usage: "overwrite the output file if it exists",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			key, err := samesame.GenerateKey(cmd.String("alg"))
			if err != nil {
				return err
			}
			data, err := samesame.MarshalPrivateKeyPEM(key)
			if err != nil {
				return err
			}
			if err := writePrivate(cmd.String("out"), data, cmd.Bool("force")); err != nil {
				return err
			}

			k, err := samesame.PublicJWK(key)
			if err != nil {
				return err
			}
			id, _ := k.KeyID()
			fmt.Fprintln(cmd.Root().Writer, id)
			return nil
		},
	}
}

func directoryCommand() *cli.Command {
	return &cli.Command{
		Name:      "directory",
		Usage:     "print the key directory JSON for one or more keys",
		ArgsUsage: "KEY.pem [KEY.pem...]",
		Description: "Prints the HTTP Message Signatures Directory to serve at\n" +
			samesame.WellKnownPath + " with media type\n" +
			samesame.MediaTypeDirectory + ".\n" +
			"Only public keys are included. List several keys to publish a new key\n" +
			"before rotating to it. Keys may be private or public PEM files.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "out",
				Aliases: []string{"o"},
				Usage:   "file to write the directory to instead of standard output",
			},
			&cli.BoolFlag{
				Name:  "pretty",
				Usage: "indent the JSON",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() == 0 {
				return errors.New("directory: at least one key file is required")
			}

			var pubs []crypto.PublicKey
			for _, path := range cmd.Args().Slice() {
				pub, err := readPublicKey(path)
				if err != nil {
					return err
				}
				pubs = append(pubs, pub)
			}

			data, err := samesame.MarshalDirectory(pubs...)
			if err != nil {
				return err
			}
			if cmd.Bool("pretty") {
				var buf bytes.Buffer
				if err := json.Indent(&buf, data, "", "  "); err != nil {
					return err
				}
				data = buf.Bytes()
			}
			data = append(data, '\n')

			if out := cmd.String("out"); out != "" {
				return os.WriteFile(out, data, 0o644)
			}
			_, err = cmd.Root().Writer.Write(data)
			return err
		},
	}
}

func keyIDCommand() *cli.Command {
	return &cli.Command{
		Name:      "keyid",
		Usage:     "print the keyid (JWK SHA-256 thumbprint) of each key",
		ArgsUsage: "KEY.pem [KEY.pem...]",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() == 0 {
				return errors.New("keyid: at least one key file is required")
			}

			for _, path := range cmd.Args().Slice() {
				pub, err := readPublicKey(path)
				if err != nil {
					return err
				}
				k, err := samesame.PublicJWK(pub)
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				id, _ := k.KeyID()

				if cmd.Args().Len() == 1 {
					fmt.Fprintln(cmd.Root().Writer, id)
				} else {
					fmt.Fprintf(cmd.Root().Writer, "%s\t%s\n", id, path)
				}
			}
			return nil
		},
	}
}

// readPublicKey reads a private or public key PEM file and returns the
// public key.
func readPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block != nil && block.Type == "PUBLIC KEY" {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return pub, nil
	}

	key, err := samesame.ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key.Public(), nil
}

// writePrivate writes a private key readable only by its owner. It refuses
// to replace an existing file unless force is set.
func writePrivate(path string, data []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists, use --force to overwrite it", path)
		}
		return err
	}
	// O_TRUNC keeps an existing file's mode, so tighten it explicitly.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
