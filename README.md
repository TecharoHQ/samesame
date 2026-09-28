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

`FetcherOptions.DirectorySignatures` controls directory response
signatures:

- `DirectorySignaturesPrefer` (default): an unsigned directory is
  accepted. If the directory has signatures, each key must have a valid
  signature, or the fetcher drops it.
- `DirectorySignaturesRequire`: the fetcher drops each key that does not
  have a valid signature. All keys from an unsigned directory are dropped.
- `DirectorySignaturesIgnore`: the fetcher does not check signatures.

Dropped keys are in `Directory.Invalid` with `ErrDirectoryUnbound`.

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
h, err := samesame.NewDirectoryHandler([]crypto.Signer{privateKey}, samesame.DirectoryHandlerOptions{
	// The hosts this directory is served for. Other hosts get 421.
	Authorities: []string{"bot.example"},
})
if err != nil {
	return err
}

mux.Handle(samesame.WellKnownPath, h)
```

The handler publishes only the public keys. Each response has one
signature per key, which proves that the operator of that origin holds
the key. The signatures are bound to the requested host, so the handler
signs only for the hosts in `Authorities`. Otherwise anyone could get
proofs that bind your keys to their own domain. Signatures are cached per
host for up to an hour.

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

### Serving the directory as a static file

To serve the directory from nginx or Caddy instead of `NewDirectoryHandler`,
use `--sign-for`:

```sh
samesame directory bot.key next.key \
	--sign-for bot.example \
	--out /srv/www/http-message-signatures-directory
```

This writes the directory to `--out` exactly as it must be served. It then
prints an nginx `location` block and a Caddy `handle` block that serve that
file with:

- the media type `application/http-message-signatures-directory+json`;
- `Cache-Control` (set with `--max-age`);
- `Content-Digest`;
- one directory response signature per key.

Use `--format nginx` or `--format caddy` to print only one of them.

These signatures prove that you hold the keys. Some verifiers require them,
for example Cloudflare. They cover only the host and the body, so they can
be static headers. Keep these points in mind:

- The signatures expire after `--lifetime` (default 30 days). The printed
  config shows the exact time. Run the command again before then, and every
  time the keys change.
- Give every host that verifiers use to reach the directory as its own
  `--sign-for`. A signature for one host does not work for another host.
- Do not compress this file. `Content-Digest` covers the exact bytes that
  the server sends. The nginx block turns gzip off. If your Caddy site uses
  `encode`, limit it to other paths, as the printed comment shows.
- In nginx, an `add_header` in the `location` block replaces the
  `add_header` directives that the `server` block would give it.

### Serving a folder of keys

`samesame serve` serves the directory for every `.pem` private key in a
folder. It watches the folder, so you can add or delete a key file to
rotate keys without a restart:

```sh
samesame serve --keys ./var --authority bot.example --bind :8080
```

- Responses carry directory signatures for each `--authority`. Other hosts
  get 421. Repeat `--authority` for each host verifiers use.
- If a `.pem` file does not parse, for example while it is being written,
  the previous keys stay served until the next good reload.
- With no keys in the folder, it answers 503.
- It also reloads every `--poll` (default one minute), in case a change
  event is missed.
- `--keys`, `--authority`, and `--bind` can also be set with
  `SAMESAME_KEYS`, `SAMESAME_AUTHORITY`, and `SAMESAME_BIND`.

In Go, the same operations are `GenerateKey`, `MarshalPrivateKeyPEM`,
`ParsePrivateKeyPEM`, `PublicJWK`, `MarshalDirectory`, and
`SignStaticDirectory`.

## Docker

The image runs `samesame serve`. It is published to
`ghcr.io/techarohq/samesame`.

```sh
docker run -d -p 8080:8080 \
	--user "$(id -u):$(id -g)" \
	-v "$PWD/var:/keys:ro" \
	-e SAMESAME_AUTHORITY=bot.example \
	ghcr.io/techarohq/samesame:latest
```

- Mount your folder of `.pem` private keys at `/keys`. The container keeps
  watching it.
- For several hosts, give `SAMESAME_AUTHORITY` as a comma-separated list,
  for example `bot.example,www.bot.example`.
- The image runs as the non-root user 65532. Private keys usually have mode
  `0600`, so the container cannot read them unless it runs as their owner.
  Use `--user` as in the example. In Kubernetes, use `fsGroup` with a
  Secret `defaultMode` of `0440`. If the container cannot read the keys,
  it logs `permission denied` and answers 503.
- `samesame --version` prints the version that the Go toolchain stamped
  from git.

To build the image:

```sh
docker buildx bake local                  # samesame:local, for this machine
VERSION=v1.2.3 docker buildx bake --push  # linux/amd64 and linux/arm64
```

The Docker workflow runs as follows:

- Each pull request builds the image without pushing it.
- Each push to `main` or `develop` pushes a branch tag and a `sha-` tag.
- Each release pushes `vX.Y.Z`, `vX.Y`, and `latest`.
- `.dockerignore` keeps `var/` and all `*.pem` files out of the build
  context.

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
