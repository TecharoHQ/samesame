# [1.0.0](https://github.com/TecharoHQ/samesame/compare/v0.0.0...v1.0.0) (2026-09-28)


### Features

* basic functionality ([#5](https://github.com/TecharoHQ/samesame/issues/5)) ([57c8f0e](https://github.com/TecharoHQ/samesame/commit/57c8f0e10ccca0ae5908e118cab4ee3152b6947c)), closes [#4](https://github.com/TecharoHQ/samesame/issues/4) [#8](https://github.com/TecharoHQ/samesame/issues/8) [#1](https://github.com/TecharoHQ/samesame/issues/1) [#1](https://github.com/TecharoHQ/samesame/issues/1)


### BREAKING CHANGES

* NewDirectoryHandler returns an error unless
DirectoryHandlerOptions.Authorities lists the hosts to serve.

Assisted-by: Claude Opus 5.5 via Claude Code
Signed-off-by: Xe Iaso <me@xeiaso.net>

* fix(nonce)!: scope nonces per agent and evict instead of refusing

MemoryNonceStore had one global capacity and refused new nonces when
full, which the verifier reports as unverified. Anyone with their own
key directory could fill it with validly signed requests carrying
24 hour expiries and make every other agent unverifiable for a day.

Nonces are now scoped by the agent's identifier, or keyid for static
keys, so agents cannot collide. When the store is full it evicts the
soonest-expiring nonce of the scope holding the most entries, found
in constant time, so a flood degrades replay protection for the
heaviest scope, usually the flooder, instead of breaking
verification for everyone. Evicted counts these events, and the
expiry heap is compacted so a sustained flood cannot grow memory
past twice the capacity.

Result.NonceChecked reports whether a nonce store actually checked
the signature's nonce.
* NonceStore.CheckAndRecord takes a scope argument,
and MemoryNonceStore no longer returns ErrNonceStoreFull.

Assisted-by: Claude Opus 5.5 via Claude Code
Signed-off-by: Xe Iaso <me@xeiaso.net>
