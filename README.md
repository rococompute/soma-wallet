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

## Session policy model

`wallet_session.soma` is a pure, typed state machine, separate from the served page.
It moves through Locked, KeyImported, PsbtLoaded, Approved, Signing (a pending
permission with approval consumed), and Signed. It holds opaque numeric key
handles and parsed/signed PSBT references only. The PSBT reference binds a parser
handle and an exact-content digest; their production and validation belong to
the future trusted parser/key-store integration. No key bytes are represented.

A review event approves the exact PSBT reference. Loading a PSBT (even the same
one) or importing a key discards prior approval; requesting signing consumes it.
Completion accepts an external signed-result reference for the pending PSBT.
Lock/reset drops every reference and permission. `wallet_session.exp` proves general
policy properties, and `tests/session.soma` checks the happy path and rejected
transitions with proof-checked equalities in `./scripts/check`.

This is a state machine only: key import, parsing, cryptographic signing and
export remain unavailable in the UI. `complete_sign` neither creates nor verifies
signatures. A future IO driver must own one authoritative session, replace it
with each successful result, serialize events, and never reuse old immutable
states or accept model constructors from clients. It must release/erase key-store
material on lock; dropping a handle alone is not secret-memory erasure.

## PSBT v0 parsing and BIP 143 digest

`wallet_psbt.soma` is a pure, bounded parser/serializer for PSBT v0 (BIP 174)
with a legacy-serialized unsigned transaction (versions 1 and 2), and the native
P2WPKH SIGHASH_ALL digest (BIP 143). It rejects bad magic, truncation,
noncanonical or oversized CompactSize lengths, duplicate keys, invalid key
lengths for fixed-key types, missing unsigned transactions, PSBT versions other
than 0, witness-serialized or scriptSig-bearing unsigned transactions, empty or
oversized input/output lists, out-of-range amounts and trailing bytes, each with
a typed error. Limits: 100000 PSBT bytes, 64 map entries, 64 inputs/outputs,
128-byte keys, 10000-byte scripts. Entries are kept in order, so a parsed PSBT
serializes back to its exact bytes. The digest requires a P2WPKH witness UTXO
and SIGHASH_ALL (or no sighash entry). `tests/psbt.soma` checks BIP 143's
native P2WPKH example (fields, round trip, digest `c37af311...`) framed as a
PSBT, and the rejections. Not yet: base64 input, BIP 174's published PSBT
vectors, non-witness UTXO checks, and wiring into the UI or signer.

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

## Runtime signing primitive

`crypto/signer.c` adds an import-free WASM primitive using the pinned
libsecp256k1. It accepts all 32 key and digest bytes at runtime, derives a
compressed public key, and produces RFC6979 deterministic, low-S ECDSA in DER
and compact form after verifying the signature. `crypto/signer.definition`
uses numeric types supported by Soma's existing ABI; `crypto/signing.soma`
decodes statuses and public bytes into distinct result/error constructors.
The original public scalar-one `probe` remains available unchanged.

The bridge stages a single operation: begin with exact lengths, set indexed
bytes, derive/sign, read public outputs, then clear. Every operation consumes
and clears key/digest staging, including errors; volatile stores also clear
the context workspace. Clear/lock clears public outputs too. There are no key
readers. Callers must serialize this effectful interface inside the unikernel,
use runtime input, branch on every status, and never supply secrets in bare
compile-time terms, URLs, browser state or logs. The wrapper does not erase
copies held by its caller or provide a vault, entropy source, or blinded context.

`tests/signer-check.mjs` checks public scalar multiples, pinned published
bitcoinjs RFC6979 vectors, independent Node/OpenSSL signature verification,
malformed inputs and clearing. `tests/runtime_signer.soma` and its Python boot
check exercise the typed bridge with a public fixture chosen at runtime.
This primitive is not connected to PSBT parsing, transaction approval, or the UI;
wallet signing and signed-PSBT export remain unavailable.

## Dependency provenance

`vendor/secp256k1/` is copied from Bitcoin Core libsecp256k1 v0.6.0, commit
`0cdc758a56360bf58a851fe91085a327ec97685a`. It retains its MIT license in
`vendor/secp256k1/COPYING`. `crypto/crypto_probe.c` is a test wrapper compiled to
WASM without host imports and called through Soma's existing `.definition` API.
BIP 143 and BIP 174 are the protocol references for the planned transaction work.

This is a development experiment, not an audited or production-ready wallet.
