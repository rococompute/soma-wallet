# Soma Wallet

A personal-use, offline Bitcoin signing wallet UI, defined with Soma's existing
Reason-style JSX and served by a MirageOS unikernel. Private keys belong in the
offline signing unikernel. This development baseline does not yet import keys,
parse PSBTs, or expose signing endpoints; its sign button is disabled.

The existing Soma runtime has been exercised without source changes: a host-only
unikernel served a JSX page, and a separate unikernel derived a known compressed
public key, signed and verified a digest with Bitcoin Core libsecp256k1, rejected
a modified signature, and rejected a zero private key. The proof-of-capability
code is in `crypto/`; it uses the public scalar-one test key, not a wallet key.

## Development

Requires the existing local Soma checkout/toolchain, opam switch `hvf` with the
Solo5/Mirage tools, Python 3, Node.js, and `timeout`. Rebuilding the app-local
cryptography module needs Zig; checks rebuild it from the vendored source. No Soma source changes are in scope.

```sh
./scripts/check               # serialized builds and an actual signing-image boot
./scripts/build-crypto        # rebuild the pinned, import-free WASM test bridge
./scripts/run                 # serve the UI on an isolated host-only vmnet network
```

The market's `.plan` contains the remaining application work. Its scope is this
repository only. There are five diplomats: `claude-1`, `claude-2`, `codex-1`,
`codex-2`, and `muse`. The original Pantheon cmux integration displays plan.md and
watchdog on the left and a chat plus node tab for each diplomat on the right.
There is no Club View in this run. Network keys and run records live outside this
repository under `../.pantheon-wallet-dogfood/` and must never be committed.

First-version signing is constrained to testnet/regtest, PSBT v0, native P2WPKH
and SIGHASH_ALL. Unsupported transactions must be rejected, and the user must
review outputs and fees before a fresh approval can authorize signing. The wallet
never broadcasts transactions. Encrypted persistence must remain disabled until
its authenticated-encryption, KDF and restart tests pass. Do not use real funds or
real user keys with this development build.

## Dependency provenance

`vendor/secp256k1/` is copied from Bitcoin Core libsecp256k1 v0.6.0, commit
`0cdc758a56360bf58a851fe91085a327ec97685a`. It retains its MIT license in
`vendor/secp256k1/COPYING`. `crypto/crypto_probe.c` is a test wrapper compiled to
WASM without host imports and called through Soma's existing `.definition` API.
BIP 143 and BIP 174 are the protocol references for the planned transaction work.

This is a development experiment, not an audited or production-ready wallet.
