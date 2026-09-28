# Plan: Web Bot Auth for samesame (build from scratch)

## Context

`samesame` is meant to be the Web Bot Auth implementation for Anubis. Right now it has
no implementation: `samesame.go` is just `package samesame` and `samesame_test.go` has
one empty test. The only content is the specs in `docs/RFC/`:

- `rfc9421.txt`: HTTP Message Signatures
- `draft-meunier-web-bot-auth-architecture-04.txt`: web-bot-auth profile (tag, keyid, nonce, status codes)
- `draft-meunier-http-message-signatures-directory-04.txt`: key directory, `Signature-Agent`, well-known URI
- `draft-meunier-webbotauth-registry-01.txt`: Signature Agent Card metadata (out of scope, see below)

Anubis (`../anubis`) does not reference web bot auth yet. Decisions made with the user:

- **Scope:** full stack. That means a verifier (for Anubis), a signer (for bot operators and
  for end-to-end tests), and a directory server handler.
- **Core:** wrap an existing RFC 9421 library instead of hand-rolling one.
- **Go version:** requiring Go 1.27 is OK.

**Library choice: `github.com/yaronf/httpsign`.** Its go.mod requires Go 1.27 and pulls in
`dunglas/httpsfv` and `lestrrat-go/jwx/v4`. According to its docs, it covers every hard
part of this work:

- `RequestDetailsByTag(req, "web-bot-auth")` returns keyid, alg, created, expires, nonce and
  tag before any crypto runs. The verifier needs this to pick a key and fetch a directory.
- `WithAssociatedRequest` / `WithResponse` handle the `;req` flag. The directory response
  signature needs this (`"@authority";req`).
- `SetNonceValidator`, `SetRejectExpired`, `SetNotOlderThan`, `SetAllowedAlgs` and
  `SetKeyID` on the verifier. `SetTag`, `SetNonce`, `SetExpires` and `SetKeyID` on the signer.
- `jwx` provides JWK parsing and the RFC 7638 / RFC 8037 thumbprint for keyids.

The alternative is `remitly-oss/httpsig-go`, which targets Go 1.22 and already shares
`golang-jwt` with Anubis. It stays the fallback if step 0 fails.

## Step 0: Check the library against the spec (before writing anything else)

Write throwaway tests in `samesame_test.go` against httpsign:

1. Verify the draft Appendix A.2 Ed25519 vectors (RFC 9421 B.1.4 test key) and the A.1
   RSA-PSS vectors (B.1.2 key). Check `alg`, `nonce` and `tag` round-trip correctly.
2. Parse `sig2=("@authority" "signature-agent";key="sig2")`. This is a dictionary member
   component (`;key=`). Confirm httpsign supports it.
3. Verify a response signature that covers `"@authority";req`.

If any of these fail, stop and switch to remitly, or report the gap to the user.

## Package layout (one flat package `samesame`, files by concern)

| File           | Contents                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `samesame.go`  | Constants: `TagWebBotAuth = "web-bot-auth"`, `TagDirectory = "http-message-signatures-directory"`, `MediaTypeDirectory = "application/http-message-signatures-directory+json"`, `WellKnownPath = "/.well-known/http-message-signatures-directory"`. Sentinel errors.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `directory.go` | `Directory{Keys []jwk.Key}`: parse and validate (drop keys that are malformed, not `use:sig`, outside `nbf`/`exp`, or whose `kid` differs from the computed thumbprint). `Thumbprint(jwk.Key) (string, error)` returns base64url SHA-256. `KeyByID`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `agent.go`     | Parse `Signature-Agent` as an SF dictionary with httpsfv. Each member must be a String holding an `https`, `http` or `data` URI. Decode `data:` URIs with the directory media type, as plain or base64. Invalid input makes the whole header be ignored (spec: MAY).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `fetch.go`     | `Fetcher`: fetch directories over HTTP with a cache. Honor `Cache-Control: max-age`, with a floor and a ceiling. Check the content type. Verify the per-key response signatures (`tag=http-message-signatures-directory`, `"@authority";req`) and drop keys that have no valid signature. Use singleflight per URL. **SSRF hardening** is required because the URL comes from the attacker: HTTPS only by default, a dialer `Control` hook that rejects loopback, private, link-local and ULA addresses, a response size cap, a timeout, and an optional host allow-list.                                                                                                                                                                                                                                  |
| `verify.go`    | `Verifier` with `Verify(r *http.Request) (*Result, error)`. Flow: (1) `RequestDetailsListByTag(web-bot-auth)`. (2) Require `created`, `expires` and `keyid`, require `@authority` or `@target-uri` to be covered, and require `expires - created <= MaxValidity` (default 24h). (3) If `Signature-Agent` is present, the signature must cover it (`;key=label`). (4) Resolve keyid from static trusted keys, then from the directory named by `Signature-Agent`. (5) Build an httpsign verifier from the JWK with alg allow-list, clock skew, and the `NonceStore` callback. (6) Return `Result{KeyID, Label, Agent *url.URL, Key, Nonce}`. Reject plaintext requests unless `AllowInsecure` is set (arch 5.1). Take the scheme from config or a trusted proxy header, because Anubis runs behind proxies. |
| `nonce.go`     | `NonceStore` interface (`Seen(ctx, nonce string, until time.Time) (bool, error)`) plus an in-memory TTL implementation. Anubis can plug in its own store backend later.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `errors.go`    | Typed errors that map to HTTP status codes: parse failure 400, bad or missing signature 403, replayed nonce 429. `WriteChallenge(w, err)` sets `Accept-Signature` with the web-bot-auth params (arch 4.3).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `sign.go`      | `Signer`: built from an Ed25519 key (or any `crypto.Signer` or JWK). Sets keyid to the thumbprint, `tag=web-bot-auth`, created and expires (default 1h, capped at 24h), and a 64-byte base64url random nonce. Covers `@authority`, plus `signature-agent;key=<label>` when an agent URL is configured. `Sign(r *http.Request) error` and `Transport(http.RoundTripper) http.RoundTripper`.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `handler.go`   | `DirectoryHandler(keys []SigningKey) http.Handler`: serves the JWKS with the right media type and `Cache-Control`. Signs the response once per key with `tag=http-message-signatures-directory` and `"@authority";req`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

Out of scope for this pass: `x5c` / AIA delegation (the draft calls it experimental) and
the Signature Agent Card registry draft. Each can follow as its own change.

## Tests (table-driven, per `xe-go:go-table-driven-tests`)

- `directory_test.go`: the directory draft example key must give thumbprint
  `NFcWBst6DXG-N35nHdzMrioWntdzNZghQSkjHNMMSjw`. Also cover the `nbf`/`exp` window,
  mismatched `kid`, and malformed JSON.
- `agent_test.go`: https, http and data URIs (plain and base64). Reject bad schemes,
  non-string members and a wrong data media type. Include the data-URI example from
  directory draft A.4.
- `verify_test.go`: the architecture draft A.1 and A.2 vectors with a pinned clock.
  Negative cases: wrong tag, missing expires, expired, validity over 24h, `@authority` not
  covered, `Signature-Agent` present but not covered, unknown keyid, replayed nonce, plain
  HTTP.
- `fetch_test.go`: `httptest.NewTLSServer` serving `DirectoryHandler`. Cover cache hit and
  miss, max-age handling, dropping keys without a valid signature, the size cap, and
  loopback being blocked by default (the test turns the block off explicitly).
- `e2e_test.go`: `Signer.Transport`, then a TLS test server running `DirectoryHandler` and
  a `Verifier` middleware, then `Result`.
- `FuzzParseSignatureAgent` and `FuzzVerify`, which must never panic on arbitrary headers.

## Repo housekeeping

- `go.mod`: `go 1.27`. Add `yaronf/httpsign`, `lestrrat-go/jwx/v4` and
  `golang.org/x/sync` (singleflight).
- `.github/workflows/ci.yml`: remove `oldstable` from the matrix, because Go 1.26 cannot
  build a 1.27 module. Also fix the codecov condition: it checks `'latest'`, which never
  matches the matrix, so it should check `'stable'`.
- `README.md`: short usage for the verifier (Anubis), the signer and the handler.

## Order of work

0. Library check (above). 1. `samesame.go`, `directory.go`. 2. `agent.go`.
1. `sign.go`. 4. `nonce.go`, `errors.go`, `verify.go`. 5. `handler.go`, `fetch.go`.
2. e2e and fuzz tests, README, CI. Use TDD for each step and one conventional commit per step.

## Verification

- `go test -race ./...` and `go vet ./...` pass. Run the fuzz targets briefly
  (`go test -fuzz=FuzzVerify -fuzztime=30s`).
- The draft test vectors pass: arch A.1 and A.2, directory A.1 thumbprint, directory A.4
  data URI.
- The e2e test proves the whole path: signer, then directory fetch with signature
  validation, then verification.
- Optional manual check: point the verifier at Cloudflare's public web-bot-auth test
  directory to confirm interop with a real deployment.
