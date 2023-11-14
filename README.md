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
a typed error. Public entry points also reject any integer outside the byte
range 0..255 (`ByteOutOfRange`), and the total output value must not exceed
MAX_MONEY (`TotalAmountOutOfRange`); per-output amounts are each capped first,
so the bounded sum cannot overflow. Limits: 100000 PSBT bytes, 64 map entries,
64 inputs/outputs, 128-byte keys, 10000-byte scripts. Entries are kept in
order, so a parsed PSBT serializes back to its exact bytes. The digest
requires a P2WPKH witness UTXO and SIGHASH_ALL (or no sighash entry), and
explicitly rejects a selected input carrying a non-witness UTXO, redeem
script or witness script (`UnsupportedNonWitnessUtxo` /
`UnsupportedRedeemScript` / `UnsupportedWitnessScript`); those entries are
still preserved by the parser for round trips, never used for a digest.
`tests/psbt.soma` checks BIP 143's native P2WPKH example (fields, round trip,
digest `c37af311...`) framed as a PSBT, and the rejections;
`tests/psbt_validation.soma` (with `.exp`) adds byte-range, amount-sum
boundary, conflicting-metadata and unknown-entry round-trip checks, and
`tests/test_psbt_vectors.py` recomputes the BIP 143 digest independently
with hashlib. Fixture provenance: BIP 143's published native-P2WPKH example,
framed per BIP 174 (both at bitcoin/bips). Strict Base64 text input is
accepted by `parse_psbt_base64`: canonical padded Base64 only (including
zero unused trailing bits in the final group, so encodings cannot alias),
decoded four characters at a time and rejected with `InputTooLarge` as
soon as the decoded length would exceed the PSBT limit, with typed
`InvalidBase64Char`/`InvalidBase64Padding` errors (checked in
`tests/psbt_base64.soma`/`.exp` and `tests/test_psbt_base64.py`).
Not yet: BIP 174's
published base64 PSBT vector suite vendored verbatim, P2SH/P2WSH or
non-witness-UTXO digest policies, and wiring into the UI or signer.

## Testnet/regtest key import and public identity

`wallet_keys.soma` is a pure, bounded layer inside the signing unikernel: it
decodes a compressed testnet WIF supplied as 52 ASCII bytes (strict Base58Check
checksum, version, compression marker and secp256k1 scalar range; mainnet WIF,
bad checksums, invalid characters, wrong lengths and zero/out-of-order scalars
are rejected with typed errors, and length checks traverse only a bounded
prefix), derives HASH160 and Bech32 P2WPKH addresses for explicit testnet
(`tb`) or regtest (`bcrt`) selection, and checks a P2WPKH witness script
against the imported key's hash (`Owned` / `NotOwned` / `UnsupportedScript`).
Public-key and witness-program inputs are validated as octets
(`ByteOutOfRange`), and the internal RIPEMD-160 is restricted to inputs of at
most 4096 bytes (`InputTooLong`, never a truncated hash). Public results
contain only the network, compressed public key, its hash and the address;
the decoded key type is internal and must never be serialized, logged or
sent to a browser. Public keys are obtained from the pinned WASM bridge
(`crypto/signing.soma`); ownership alone authorizes no signature, and fresh
session approval is still required. Dropping a decoded key does not zeroize
runtime copies, so a future lock driver must also clear the bridge and
abandon the value. Checked by `tests/keys.soma`/`.exp` (published
scalar-one fixtures and RIPEMD-160 vectors) and independently recomputed by
`tests/test_keys.py`. Not yet wired to key entry, the session driver or PSBT
signing; no browser key entry, HTTP signing endpoint or persistence was added.

## Published BIP 174 vectors and key-data rules

`tests/bip174.soma` checks BIP 174's published test vectors
(https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki, "Test Vectors"),
embedded as the hex of their Base64 strings; `tests/test_bip174_vectors.py` keeps
the Base64 verbatim and checks every embedded byte. All 20 invalid vectors are
rejected with their specific typed errors; the 8 valid vectors with inputs
re-serialize to their exact bytes, and the first's transaction fields are checked;
the two valid zero-input vectors are rejected by this wallet's policy (nothing to
sign). Key-data lengths are checked for the key types BIP 174 and BIP 371 fix
(pubkey-keyed partial signatures and BIP 32 paths, 78-byte global xpubs, hash
preimages, Taproot keys); other key types are preserved unchanged. `parse_psbt`
and `parse_tx` find their 100000-element bound by a walk of at most that length
before any full scan. Not yet: BIP 371 control-block lengths and cross-checking
non-witness UTXOs against their outpoints.

## Wallet UI view model

`wallet_ui.soma` is the pure view model for the wallet pages: it maps each
`wallet_session` state to a page (locked, identity, review, approved,
signing, signed) and to per-action availability with honest reasons
(checked in `tests/ui.soma`/`.exp`). Key import, PSBT load and approval
become available only in the states the session model allows; signing and
signed-PSBT export are reported unavailable with their reason in every
state until a session driver connects them, so no page built on this
model can present an unconnected operation as working. Session errors
have user-facing messages here. `main.soma` still serves its locked page
unchanged in this step; adopting the model in the served markup and
wiring page actions to the driver remain follow-up work.

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

## Runtime public-identity and input-ownership adapters

`wallet_key_runtime.soma` connects bounded compressed testnet WIF validation to
libsecp256k1 inside the signer. `preview_wif_identity` returns only the network,
compressed public key, HASH160 and tb1/bcrt1 address, or typed key/bridge errors.
It clears previous staging before decoding and clears inputs and public outputs
after success and failure, including malformed WIF. `clear_key_bridge` is the
explicit bridge lock cleanup. Call this effectful single-operation bridge only
from a serialized runtime driver, never as a compile-time secret expression.
Dropping immutable Soma values does not zeroize runtime copies; decoded scalar
and WIF copies must remain inside the signer and be abandoned after use. This
adapter does not retain key handles or implement an authoritative session store.

`wallet_input_owner.soma` checks identity consistency, input range, the digest's
`metadata_ok` and `sighash_all_ok` policy, and then the bounded witness UTXO's
native P2WPKH program. Unsupported metadata, scripts and sighashes are typed
rejections. `Owned` is a comparison with a PSBT claim, not UTXO authentication
or signing permission; fresh session approval is still required.

New ownership proof tests and `tests/key_runtime.soma` exercise public scalar-one
fixtures from `tests/keys.soma` (independently checked by `test_keys.py`). The
booted image selects the fixture at runtime, checks both network addresses,
checks empty bridge inputs/outputs, and stages prior input before testing mainnet,
length, checksum and scalar rejection cleanup. No WIF or scalar is printed.
Retained key handles, secret-memory lifecycle, secure key entry, session/UI
integration, PSBT signing and persistence remain unavailable.
