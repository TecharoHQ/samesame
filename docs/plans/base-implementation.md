# Plan: Web Bot Auth for samesame (build from scratch)

## Context

`samesame` is meant to be the Web Bot Auth implementation for Anubis. The repo had no
implementation. The specs are in `docs/RFC/`:

- `draft-ietf-webbotauth-httpsig-protocol-00.txt` (2026-09-01): the working group
  document. It replaces the old architecture and directory drafts and defines the
  web-bot-auth profile, `Signature-Agent`, the key directory and the well-known URI.
  All section numbers below refer to it.
- `rfc9421.txt`: HTTP Message Signatures.
- `draft-meunier-webbotauth-registry-03.txt`: Signature Agent Card (out of scope).

Decisions:

- **Scope:** full stack. That means a verifier (for Anubis), a signer, and a directory
  server handler.
- **Core:** wrap `github.com/yaronf/httpsign` (Go 1.27, `httpsfv`, `jwx/v4`). Step 0
  confirmed that it supports pre-verification details (`RequestDetailsListByTag`),
  dictionary member components (`AddDictHeader`), the `;req` flag
  (`AddRequestComponent`) and tag allow-lists.
- **`Signature-Agent` types:** v1 supports only `type=directory`, which is the default.
  Members with `jwks_uri`, `cimd` or an unknown type are ignored, which 5.2.1 permits.
- **Legacy bare-string `Signature-Agent`:** the verifier accepts it (5.2.1 MAY). The
  signer never sends it.
- **Directory response signatures:** the handler always emits them. Verifying them is
  opt-in, because 5.5 / App B let a verifier use directly resolved keys without proof.

## Identity model (Sec 4, 5.4, 6.10)

- The identifier is the URL the verifier resolved: for `directory`, that is
  `origin + /.well-known/http-message-signatures-directory`, normalized per RFC 3986
  6.2.2 and 6.2.3. It is never the raw member value.
- Key lookup is keyed on the `(identifier, keyid)` pair (5.4 MUST).
- A key held out-of-band (static config) yields only a thumbprint identity (4.3). It
  never attributes the request to a URL (4.4 MUST NOT).
- There are three outcomes (C.1): `verified`, `invalid`, and `unverified` (discovery
  failed or key unknown). `unverified` is its own signal, not a 403.

## Package layout (one flat package `samesame`)

| File           | Contents                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `samesame.go`  | Constants: `TagWebBotAuth`, `TagDirectory`, `MediaTypeDirectory`, `WellKnownPath`, `HeaderSignatureAgent`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `directory.go` | `ParseDirectory`: parses the JWKS and drops bad keys individually (5.5.1 SHOULD). A key is dropped when it is malformed, contains private material, has `use` other than `sig`, has a `kid` that does not equal the thumbprint (5.5 MUST for the well-known URI), or is a known RFC 9421 test key (6.8 SHOULD, with an opt-out for tests). `nbf`/`exp` are honored at lookup time as local policy, because the spec is silent. Parsing also enforces a max key count (6.7). `Thumbprint(jwk.Key)` returns the RFC 7638 / RFC 8037 thumbprint.                                                                                                                                                                                                                                                                                                                                                                                                         |
| `agent.go`     | Parses `Signature-Agent`. Dictionary form: String members with a `type` Token param (default `directory`). For `directory` members, the value must be an https origin (path empty or `/`), otherwise the member is ignored. Other types are ignored. Legacy form: if the raw field starts with `"`, it is parsed as one String Item and treated as a single member keyed by the covering signature's label. Returns members with their resolved identifier URL.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `fetch.go`     | `Fetcher` resolves a directory identifier to a `*Directory`. Rules: HTTPS only; no redirects (`CheckRedirect` returns `ErrUseLastResponse`, and 3xx counts as failure); 200 only; media type check; body cap after decoding; timeout; dialer `Control` that blocks loopback, private, link-local and ULA addresses (6.7). Caching follows HTTP semantics: `Cache-Control`, `Expires`, `ETag`/`Last-Modified` with conditional GET (C.4), plus floor/ceiling clamps. A failed fetch MUST NOT evict a cached entry, while a successful fetch replaces it (6.10). Negative cache at most 5 min, exponential backoff with jitter, and `Retry-After` (C.5). singleflight per identifier plus a per-origin concurrency limit (C.3). Optional `VerifyDirectorySignatures`: checks `("@authority";req "content-digest")` with `tag=http-message-signatures-directory`, validates `Content-Digest` against the body, and rejects a future `created` (App B.1). |
| `verify.go`    | `Verifier.Verify(r) (*Result, error)`. Flow: (1) Run `RequestDetailsListByTag(web-bot-auth)` and verify each signature independently (5.2.2). (2) Require `created`, `expires` and `keyid`, and require `@authority` or `@target-uri` to be covered (5.2). Apply a configurable `MaxValidity` for `expires - created` (C.6 says it is policy; default 24h). (3) Find the covered `signature-agent` component and locate the member through its `;key=` (never by label, 6.6.1). In legacy form, the component is un-keyed. (4) Resolve the key by `(identifier, keyid)` through `Fetcher`, falling back to static keys (thumbprint identity). (5) Verify with httpsign, using an alg allow-list (no HMAC, 6.4), clock skew and the `NonceStore`. (6) Return `Result{Outcome, KeyID, Label, Identifier *url.URL, Key}`. Reject plaintext unless `AllowInsecure` is set (6.1). The scheme comes from config or a trusted proxy header.                  |
| `nonce.go`     | `NonceStore` with an atomic `CheckAndRecord(ctx, nonce, until) (fresh bool, err error)`, plus an in-memory TTL implementation with bounded size. If the store errors, the replay check fails closed: the result is not verified, and nothing claims the check ran (C.6).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `errors.go`    | Errors classified into outcomes. Status code helpers: parse failure 400 (MAY), invalid 403, replay 429 (MAY). `WriteChallenge(w, err)` sets `Accept-Signature` with the profile params (5.3).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `sign.go`      | `Signer`: built from an Ed25519 key or any `crypto.Signer` / JWK. Sets keyid to the thumbprint, `tag=web-bot-auth`, created, and expires (default 1h, capped at 24h, 5.2 RECOMMENDED). Nonce is on by default: 64 random bytes, base64url. A `Signature-Agent` origin is required (4.3 MUST), with member key and label as separate settings. Covers `@authority` and `"signature-agent";key=<member>`. Provides `Sign(r)` and `Transport(rt)`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `handler.go`   | `DirectoryHandler(keys)`: serves the JWKS (with `kid` = thumbprint) as `MediaTypeDirectory`, with `Cache-Control`, `Content-Digest: sha-256`, and one signature per key over `("@authority";req "content-digest")` with long `expires` (C.8). Supports GET and HEAD.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

Out of scope: `jwks_uri` and `cimd` member types, delegation and chaining (D.1), the
registry / Signature Agent Card, and signing multiple signatures that cover each other
(5.2.2). Verifying multiple independent signatures is in scope.

## Tests (table-driven, per `xe-go:go-table-driven-tests`)

- Vectors from Appendix E, all confirmed to verify over their printed bases:
  - E.1.1: RSA-PSS, dictionary form, label `sig2`, member `agent2`.
  - E.1.2: RSA-PSS, legacy string form.
  - E.2.1: Ed25519, dictionary form.
  - E.2.2: Ed25519, legacy string form.
  - E.2.3: signed directory response, which is also the directory fixture.

  E.x.1 use `expires=4889289600`, so those tests raise `MaxValidity` and opt out of
  the test-key denylist.

- `directory_test.go`: the thumbprint of the B.1.4 key is
  `poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U`. The spec's 5.5.1 example key (wrong
  `kid` `NFcWBst6...`) must be dropped. Also cover private material, `use:enc`,
  `nbf`/`exp`, the key-count cap, malformed JSON, and the test-key denylist.
- `agent_test.go`: an origin member is valid; a member with a path, an http member, a
  data member, or a non-string member is ignored; `jwks_uri`/`cimd`/unknown types are
  ignored; the legacy string form is accepted; `/` is accepted as the path.
- `verify_test.go`: the E vectors, plus negative cases: wrong tag, missing expires,
  expired, validity over `MaxValidity`, `@authority` not covered, `Signature-Agent`
  member not covered, member located by label instead of `;key=`, unknown keyid
  (`unverified`), replayed nonce, nonce store error, plain HTTP, and HMAC alg.
- `fetch_test.go`: `httptest.NewTLSServer` serving `DirectoryHandler`. Cover cache hit,
  conditional GET, a failed refresh keeping the cache, a successful refresh without the
  key evicting it, the negative cache, a redirect being refused, non-200, the size cap,
  loopback blocked by default, and the optional directory signature check (E.2.3).
- `e2e_test.go`: `Signer.Transport`, then TLS `DirectoryHandler`, then `Verifier`, then
  a `verified` result with the correct identifier.
- `FuzzParseSignatureAgent` and `FuzzVerify`.

## Repo housekeeping

- `go.mod`: `go 1.27` (done). Dependencies: `yaronf/httpsign`, `lestrrat-go/jwx/v4`,
  `dunglas/httpsfv`, `golang.org/x/sync`.
- `.github/workflows/ci.yml`: drop `oldstable` (Go 1.26 cannot build the module) and fix
  the codecov condition (`'latest'` should be `'stable'`).
- `README.md`: usage for the verifier, the signer and the handler.

## Order of work

0. Library check (done; E vectors will replace the -04 ones).
1. `samesame.go`, `directory.go`.
2. `agent.go`.
3. `sign.go`.
4. `nonce.go`, `errors.go`, `verify.go`.
5. `handler.go`, `fetch.go`.
6. e2e and fuzz tests, README, CI.

Use TDD and one conventional commit per step.

## Verification

- `go test ./...` and `go vet ./...` pass. CI also runs `-race`. Run the fuzz targets
  briefly.
- All Appendix E vectors pass.
- The e2e test covers the full path: sign, discover, verify.
- Optional: interop check against a public web-bot-auth deployment.
