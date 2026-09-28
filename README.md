# samesame

The Web Bot Auth implementation for Anubis.

samesame lets HTTP clients sign requests and lets servers verify who sent
them, following
[draft-ietf-webbotauth-httpsig-protocol-00](docs/RFC/draft-ietf-webbotauth-httpsig-protocol-00.txt)
on top of HTTP Message Signatures ([RFC 9421](docs/RFC/rfc9421.txt)). It
has three parts:

- `Verifier` checks signatures on incoming requests. Anubis uses this.
- `Signer` signs outgoing requests for a bot.
- `NewDirectoryHandler` serves a bot's public keys at
  `/.well-known/http-message-signatures-directory`.

It requires Go 1.27 or later.

## Verifying requests

```go
v, err := samesame.NewVerifier(samesame.VerifierOptions{
	Resolver:   samesame.NewFetcher(samesame.FetcherOptions{}),
	NonceStore: samesame.NewMemoryNonceStore(0),
})
if err != nil {
	return err
}

res, err := v.Verify(r)
switch samesame.OutcomeOf(err) {
case samesame.OutcomeVerified:
	// res.Identifier is the agent's key directory URL, for example
	// https://bot.example/.well-known/http-message-signatures-directory.
	// It is nil when the key came from VerifierOptions.StaticKeys; then
	// res.KeyID is the only identity.
case samesame.OutcomeInvalid:
	// A signature is present and wrong: bad signature, expired, replayed,
	// or not following the web-bot-auth profile.
	http.Error(w, "invalid signature", samesame.StatusCode(err))
case samesame.OutcomeUnverified:
	// Unsigned, unknown key, or key discovery failed. This is not proof of
	// anything. Treat it as a signal, not as a verdict.
}
```

The verifier:

- requires `created`, `expires`, `keyid`, and `tag="web-bot-auth"`;
- requires `@authority` or `@target-uri` to be covered;
- limits `expires - created` to 24 hours by default;
- finds the `Signature-Agent` member through the covered component's
  `;key=` parameter, and accepts the legacy string form of the header;
- refuses signatures sent over plain HTTP.

Behind a proxy that terminates TLS, set `VerifierOptions.Scheme` to read
the original scheme from a header that you trust.

`Fetcher` downloads key directories named by `Signature-Agent`. That URL
comes from the client, so the fetcher only uses https, does not follow
redirects, and refuses to connect to loopback, private, link-local, and
other non-public addresses. It also limits size, time, and concurrency. It
caches directories using the response's caching headers. If a refresh
fails, the fetcher keeps the last good directory.

## Signing requests

```go
s, err := samesame.NewSigner(privateKey, samesame.SignerOptions{
	AgentOrigin: "https://bot.example",
})
if err != nil {
	return err
}

client := &http.Client{Transport: s.Transport(nil)}
```

Supported keys are Ed25519, ECDSA P-256 and P-384, and RSA (RSA-PSS
SHA-512). By default, each signature is valid for one hour and has a
random nonce.

## Serving the key directory

```go
h, err := samesame.NewDirectoryHandler([]crypto.Signer{privateKey}, samesame.DirectoryHandlerOptions{})
if err != nil {
	return err
}

mux.Handle(samesame.WellKnownPath, h)
```

The handler publishes only the public keys. Each response has one
signature per key, which proves that the operator of that origin holds
the key.

## Managing keys with the CLI

`cmd/samesame` generates keys and the directory to publish for them.

```sh
go install github.com/TecharoHQ/samesame/cmd/samesame@latest

# Make a key. The key's keyid is printed; the file has mode 0600.
samesame keygen --out bot.key

# Print the directory JSON to serve at
# /.well-known/http-message-signatures-directory.
samesame directory bot.key

# To rotate, publish the new key next to the old one first.
samesame keygen --alg ecdsa-p256-sha256 --out next.key
samesame directory bot.key next.key

# Print the keyid of existing private or public PEM keys.
samesame keyid bot.key next.key
```

`samesame directory` prints the same JSON that `NewDirectoryHandler` serves.
If you serve the file from somewhere else, send it with the media type
`application/http-message-signatures-directory+json`. A static file cannot
carry the directory response signatures that the handler adds. Verifiers
are allowed to use keys without those signatures.

In Go, the same operations are `GenerateKey`, `MarshalPrivateKeyPEM`,
`ParsePrivateKeyPEM`, `PublicJWK`, and `MarshalDirectory`.

## Not supported yet

- `jwks_uri` and `cimd` members of `Signature-Agent`. The verifier ignores
  them.
- Delegation and certificate chains.
- The Signature Agent Card in
  [draft-meunier-webbotauth-registry](docs/RFC/draft-meunier-webbotauth-registry-03.txt).

## Development

```sh
npm ci        # commit hooks
go test ./...
```

The implementation plan is in
[docs/plans/base-implementation.md](docs/plans/base-implementation.md).
