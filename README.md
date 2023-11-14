# Soma Wallet

## Local dogfood CI

`scripts/check` uses `soma test` to check the UI, crypto smoke image and Soma
tests, then always runs the JavaScript, Python and booted-image checks. It needs
the current Soma CLI (`soma test --help`); `SOMA=/absolute/path/to/soma` selects it
explicitly. Ordinary local checks run all entry points.

For the operator's local Pantheon market, `scripts/ci-host` implements the
`MEMORY CHECKOUT COMMAND` adapter. Set `WALLET_CI_CACHE` to a private persistent
directory and configure `--ci-repo wallet 'timeout 300 ./scripts/check'` with
`--ci-sandbox /absolute/path/to/scripts/ci-host`. The adapter copies the requested
candidate's source into a retained workspace and uses its last fully passing
Git snapshot as `soma test --changedSince HEAD`'s baseline. Failed checks never
advance that baseline. Generated images are hashed before reuse; missing or
changed images invalidate test receipts. Source additions/deletions discard
compiled state, preventing a removed module from surviving in the cache.

The cache is local and disposable. Toolchain/package or runner changes widen
selection, and a cold cache runs all entry points. The shared build lock is
acquired before the 300-second execution budget begins. This host adapter runs
as the operator and is not a security sandbox.

A personal-use, offline Bitcoin signing wallet UI, defined with Soma's existing
Reason-style JSX and served by a MirageOS unikernel. Private keys belong in the
offline signing unikernel. This development baseline does not yet import keys,
parse PSBTs, or expose signing endpoints; its sign button is disabled.

The existing Soma runtime has been exercised without source changes: a host-only
unikernel served a JSX page, and a separate unikernel derived a known compressed
public key, signed and verified a digest with Bitcoin Core libsecp256k1, rejected
a modified signature, and rejected a zero private key. The proof-of-capability
code is in `crypto/`; it uses the public scalar-one test key, not a wallet key.

## Experimental vault primitive (test-only; persistence disabled)

`crypto/vault.c` and `wallet_vault.soma` add an isolated signer-local foundation,
using unchanged Monocypher 4.0.3 sources for Argon2id v19 and
XChaCha20-Poly1305. Upstream is https://github.com/LoupVaillant/Monocypher,
commit `ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f`; source/license SHA256 hashes
and license choices are recorded in `vendor/monocypher/UPSTREAM`. The existing
Zig build compiles this separate WASM module with no host imports. No cryptographic
primitive is implemented in the wallet wrapper.

Only `test_seal` / `vault_test_seal` seal data, using caller-supplied PUBLIC fixture
salt/nonce. **Never call these with real keys or passwords.** The fixed test KDF
cost is deliberately weak: 64 KiB, 3 passes, 1 lane, 32 output bytes. It permits a
booted test under the existing WASM interpreter, not password protection. The
initial 8192-KiB runtime fixture exceeded its boot budget. Production sealing
(`vault_seal`, `seal_unavailable`) always clears state and rejects with
`VaultEntropyUnavailable`. A real vault needs a distinct production format and
hardware-calibrated KDF policy; this test envelope must never silently become one.

The exact 100-byte **test** envelope is:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII `SWVT` (Soma Wallet Vault Test) |
| 4 | 1 | Version 1 |
| 5 | 1 | KDF 1 = Argon2id v19 |
| 6 | 1 | AEAD 1 = XChaCha20-Poly1305 |
| 7 | 1 | Lanes = 1 |
| 8 | 2 | Memory KiB, little endian = 64 |
| 10 | 1 | Passes = 3 |
| 11 | 1 | Reserved = 0 |
| 12 | 16 | Public test salt |
| 28 | 24 | Public test nonce |
| 52 | 32 | Ciphertext for one 32-byte test key |
| 84 | 16 | Authentication tag |

All 52 header bytes are AEAD associated data. Open requires the exact size and
fixed header/parameters before invoking the KDF, preventing attacker-selected
resource use or downgrade. Wrong passphrase and altered salt/nonce/ciphertext/tag
produce the same authentication error, with no plaintext. Unsupported headers,
versions and truncated/oversized envelopes fail with typed errors.

Entropy remains a blocker for real-key sealing. The existing `Sandbox.random`
calls `Mirage_crypto_rng.generate` in the installed runtime. A booted probe did
return a bounded byte, but boot also reported `no CPU RNG bootstrap`; this patch
does not establish the quality/source of its initial seed or restart uniqueness.
It does not substitute timestamps, deterministic PRNGs or fixtures for entropy.
A verified, seeded signer entropy path is required before enabling real sealing.
"Signer entropy evidence" below records what has since been verified about that seed.

The bridge bounds passphrases to 1..128 bytes and keys to 32 bytes, tracks every
staged byte, and clears staged passwords, scalars, derived keys and KDF workspace
after success and failure. Only the explicit signer-internal open path can read
unlocked key bytes; lock erases that buffer and every output too. The Soma wrapper
reads its result then locks on success and failure. Its `OpenedKey` is secret and
must never reach a browser/log; immutable copies in Soma/OCaml cannot be erased
by clearing WASM. There is no retained key handle or authoritative lifecycle yet.
There are no persistence calls, disk or browser storage, UI unlock controls, or
restart-persistence claims. Persistence stays disabled until signer integration,
erase-on-lock, durable format and actual persistence/restart checks pass.

New `tests/vault-check.mjs` compares the whole deterministic public envelope with
an independent libsodium Argon2id + XChaCha20-Poly1305 implementation invoked by
`vault_reference.py`. The host check requires installed libsodium (`libsodium`
on Homebrew, `libsodium23` on Debian; Python uses ctypes, no Python packages).
It checks roundtrip, wrong passphrase, every flipped envelope byte, truncation,
wrong version/parameters, incomplete/bad staging, wiped inputs and lock erasure.
A fresh WASM instance reopens the public envelope with its passphrase; this is an
instance-reset check, not persistence. `tests/vault_runtime.soma` and its new
Python boot check exercise the typed seal/open/error/cleanup path in the actual
unikernel and check that no scalar hex is logged. `./scripts/check` runs all of
these alongside the existing wallet tests. The public scalar-one key, `pub`
password, repeated 0x11 salt and repeated 0x22 nonce are test data only.

## Production vault format and KDF policy proposal

`wallet_vault_format.soma` is a pure, bounded framing layer for a future vault.
It contains no key/password input, KDF, AEAD, IO, randomness or persistence.
`parse_production` accepts syntax only; `FormatOk` does **not** mean a valid MAC,
decrypted key or permission to save/unlock anything. The SWVT test bridge remains
unchanged; production sealing still fails with `VaultEntropyUnavailable`.

Version 1 reserves magic **SWVP** and accepts exactly Argon2id v19 with
**65536 KiB (64 MiB), 3 passes, 4 lanes and a 32-byte derived key**. This is
[RFC 9106 section 4's second recommended profile](https://www.rfc-editor.org/rfc/rfc9106.html#section-4),
with a 16-byte salt. Both lower and higher costs are rejected: version 1 has one
supported profile, so a file cannot select a weak KDF or excessive workspace/time.
Four lanes affect the derived key even when computed sequentially, as explained
in [Monocypher's Argon2 documentation](https://monocypher.org/manual/argon2).
The future implementation must use all four lanes, without silently rounding or
substituting the test KDF. This policy has not been calibrated or executed in the
unikernel; it does not establish that the current interpreter can support it.

The canonical envelope is exactly **112 bytes**. Integers are little endian.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII `SWVP` |
| 4 | 1 | Format version = 1 |
| 5 | 1 | KDF = 1 (Argon2id) |
| 6 | 1 | Argon2 version = 19 |
| 7 | 1 | AEAD = 1 (XChaCha20-Poly1305) |
| 8 | 1 | Reserved flags = 0 |
| 9 | 1 | Lanes = 4 |
| 10 | 2 | Header size = 64 |
| 12 | 4 | Memory KiB = 65536 |
| 16 | 4 | Passes = 3 |
| 20 | 2 | Ciphertext size = 32 |
| 22 | 1 | Salt size = 16 |
| 23 | 1 | Nonce size = 24 |
| 24 | 16 | Salt |
| 40 | 24 | Nonce |
| 64 | 32 | Ciphertext |
| 96 | 16 | AEAD tag (distinct from the 32-byte KDF output) |

`production_aad` returns **all first 64 bytes**, including salt and nonce, for
the future AEAD operation; ciphertext and tag follow. Unknown algorithms or
versions, nonzero flags, inconsistent sizes, weak/unsupported costs, non-octets,
truncation and trailing data are typed rejections. The parser walks at most 113
list cells before rejecting oversized input and never allocates a KDF workspace.
The serializer revalidates constructed models and each bounded field; it cannot
silently truncate/normalize oversized costs or emit an invalid model. SWVT is
never upgraded or reinterpreted as SWVP. Changes to supported profiles require
an explicit format/policy review, not attacker-supplied parameter negotiation.

New `tests/vault_format.soma`/`.exp` check exact parsing, serialization and AAD,
every fixed-header byte, lower/upper KDF boundaries, byte/field/size limits and
test-format separation. Salt/nonce/ciphertext/tag mutations remain syntactically
parseable: authentication is deliberately future AEAD work. The committed public
fixture uses arbitrary ciphertext/tag patterns and is **not** an encrypted key or
valid MAC. `tests/test_vault_format.py` reconstructs its wire bytes independently
using Python `struct`, including the 32-bit cost fields and all field offsets.
These checks run under `./scripts/check`; no production KDF boot is implied.

Still required before real use: verified seeded entropy and unique salt/nonce,
production KDF/AEAD execution and hardware calibration, authenticated open before
exposing plaintext, signer/session ownership and erase-on-lock, then encrypted
persistence with actual restart tests and UI unlock. Persistence remains disabled
and this remains a development-only format proposal.

## Signer entropy evidence (probe only; sealing still disabled)

`Sandbox.random` in a booted image draws from mirage-crypto's Fortuna. The
generator is set up by `Mirage_crypto_rng_mirage.initialize` in every generated
unikernel. The runtime installed here uses a mirage-crypto build in which
`initialize` first asks the tender for 32 host bytes through the
`solo5_random` hypercall. If the tender provides them, those bytes seed Fortuna
and the host pools keep being refilled once a second. If not, it logs
`no host entropy (solo5_random unavailable)` and falls back to the CPU RNG,
which Apple silicon lacks (hence `no CPU RNG bootstrap`), or to timing-based
whirlwind seeding. In the installed solo5 `hvt` tender
(`tenders/hvt/hvt_core.c`), `hypercall_random` fills the buffer with
`arc4random_buf` on macOS and `getrandom` on Linux. `--no-random` turns that
off.

`tests/entropy_probe.soma` draws two 32-byte blocks at runtime and prints them.
They are throwaway probe values, never used as a key, salt or nonce.
`tests/test_entropy_probe.py` boots it three times with the normal tender and
once with `--no-random`. It checks that:

- normal boots never log the fallback message, while the `--no-random` control
  does, so the check is not vacuous;
- all eight blocks differ, both within one boot and across restarts;
- no block is constant or counter-like (an arithmetic progression, or fewer
  than 16 distinct bytes), and the byte distribution is not grossly skewed.

What this verifies: under the normal tender, the signer's Fortuna is seeded and
refreshed from the host OS CSPRNG, and its output varies across restarts.

What it does not verify: statistical randomness (no test suite was run), the
host CSPRNG itself, behavior under tenders without the random feature (they
silently fall back to weaker seeding), and any guarantee that the image is
always run without `--no-random`. A production salt/nonce path must therefore
require host entropy: it should fail closed when `solo5_random` is unavailable
rather than rely on the fallback. Sandbox does not currently report which seed
was used, and the reseed time and source mix are internal to mirage-crypto.

Nothing here produces production salts or nonces. Production sealing
(`vault_seal`), signer key lifecycle integration and persistence all remain
disabled.


## SWVP production seal/open primitives (host-verified; booted sealing blocked)

`crypto/vault.c` now also exports SWVP v1 production primitives beside the
unchanged SWVT test entry points: `vault_prod_begin`, `vault_prod_put`,
`vault_prod_seal`, `vault_prod_open`, the readers `vault_prod_envelope_byte` and
`vault_prod_opened_byte` (explicit signer-internal open path only), and the
boolean audit `vault_prod_cleared`. They use exactly the merged
`wallet_vault_format.soma` profile: Argon2id v19 with 65536 KiB, 3 passes and
4 lanes, and XChaCha20-Poly1305 with the complete 64-byte SWVP header as
associated data, producing or opening the 112-byte envelope. Open compares the
24 framing/profile header bytes before growing the workspace or running the
KDF, so SWVT bytes, unknown versions and weak or excessive costs never reach
Argon2. The 64 MiB Argon2 workspace comes from `memory.grow` on first use, so
SWVT users keep the small initial memory. It is wiped after every KDF, and all
staged passwords, keys, derived keys and outputs are wiped on success and
failure. `vault_lock` now also erases the production state. Salt and nonce are
caller-supplied: nothing here generates randomness.

`tests/vault-prod-check.mjs` compares a whole public SWVP envelope byte for byte
with an independent reference: Argon2id from Node's OpenSSL-backed
`crypto.argon2Sync`, and XChaCha20-Poly1305 from libsodium
(`tests/vault_prod_reference.py`). It also checks round trip, wrong passphrase,
flipped salt/nonce/ciphertext/tag bytes (authentication failure, no plaintext),
all 24 framing bytes, SWVT, weak/excess memory and passes, wrong lanes and
truncation rejected before the KDF, incomplete staging, caller-written header
bytes, and wipe/lock audits. `tests/vault_prod_runtime.soma` with
`tests/test_vault_prod_runtime.py` boots the unikernel and checks the rejection
and wipe paths there.

Measured cost (this Mac, M-series, hvf): one full SWVP seal takes about 150 ms in
Node's JIT-compiled WASM (Node's native Argon2id takes about 30 ms). Inside the
booted unikernel's WASM interpreter it did not finish within 240 s
(`solo5-hvt --mem=256 -- tests/vault_prod_runtime.hvt --arg=measure`, stopped by
timeout). Production sealing and opening inside the signer is therefore blocked
on KDF execution speed, not on format or entropy. Options for a later task:
a faster WASM execution path in the runtime (outside this repository), or a
reviewed, lower but still policy-bounded profile, which needs a new format version
rather than silently weakening SWVP v1. Until then nothing seals real keys:
`vault_seal` still fails closed, salt/nonce are not generated from entropy, and
key-slot integration, persistence and UI unlock remain unavailable.

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

## Pure signing preparation and candidate export

`wallet_signing_prepare.soma` is a pure first step toward the signing driver.
`reference_for` validates bounded PSBT bytes before binding a session reference
to SHA256 of those exact bytes, including metadata. `prepare_signing` refuses
missing, stale and consumed approvals, verifies that content binding, applies
`check_psbt_input_owner`, refuses a pre-existing partial signature for this key,
and obtains the digest from `p2wpkh_sighash_all`. A successful preparation carries
the model's next `Signing` state, with approval consumed, alongside public data.
A future authoritative driver must save that state before IO, bind its key
handle to the actual imported identity/secret, serialize events, and never reuse
old immutable states or preparation values. This pure function cannot enforce
linear ownership of caller-held values and does not retain any key material.

`wallet_partial_export.soma` performs mechanical BIP 174 candidate insertion:
0x02 || compressed public key -> DER || SIGHASH_ALL, preserving all other maps
and entries. It refuses duplicates, checks minimal positive DER INTEGER framing,
re-parses serialized bytes under the parser's limits, and encodes canonical
Base64. A candidate is explicitly **not a verified signature or signed session**;
this helper does not call `complete_sign`, perform cryptography or authorize
export to a user. The runtime driver must verify libsecp256k1's DER against the
prepared digest and actual key before publishing a signed result.

New tests use a synthetic public r=1,s=1 DER value solely to check exact byte
insertion and Base64, never to claim a valid signature for the transaction.
Independent Python recomputes the BIP 143 digest and candidate framing. Pure
checks cover content substitution, consumed approval, ownership/policy failures,
index and duplicate rejection, DER shape and byte bounds. The runtime operation described below now produces bridge-verified PSBT
signatures and completes Signed in a booted fixture. The separate retained-key
slot is described below. UI sign/export wiring, multi-input batches and
finalization remain unavailable.
Nothing is broadcast.

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
have user-facing messages here. The served page (next section) is built on this model: its key-import,
approval, signing, export and lock controls render disabled with the model's
reason for the `Locked` session it serves. PSBT import and review are live;
wiring the other actions to a session driver remains follow-up work, and the
page copy says so.

## Served wallet page: PSBT import and review

`main.soma` serves `wallet_review.respond`. `GET /` shows the locked wallet and
a PSBT import form; `POST /review` with a Base64 PSBT in the form field `psbt`
decodes it (requests over 300000 characters are refused before any decoding;
`parse_psbt_base64` applies the parser's limits) and renders every output
(amount in sat and BTC, script kind, script hex, and for native P2WPKH its
testnet and regtest addresses) and the output total. It also renders every input
in transaction order (previous txid and output index, plus the amount its
witness UTXO claims, labelled as a PSBT claim) and states that no input is
selected for signing in this read-only review. The input total and fee follow:
both are unavailable unless every input has a well-formed witness-UTXO amount,
and a fee that would be negative is shown as an inconsistency, not as a missing
amount. Routes: `GET /` (anything other than `POST /review` gets this page) and
`POST /review`. Rejections show the parser's typed error in words. Live: PSBT import
and full review (public data only, no key involved). Unavailable: key import,
approval, signing, export and lock. The served session is always `Locked`, so
these actions render disabled with `wallet_ui`'s reasons, and nothing claims
they work. Responses are `text/html; charset=utf-8` with `X-Content-Type-Options: nosniff`,
`Cache-Control: no-store` and a Content-Security-Policy that allows only inline
styles and forms posted back to the page (Wire's `http_response` says text/plain,
so a browser would show the source). Framing: `serve` gives the handler only what a
connection sends first. A POST is reviewed only when that read holds complete
headers, exactly one Content-Length (one to six digits), no Transfer-Encoding,
and a body of exactly that length. A shorter body, including a valid PSBT prefix
whose rest would come later, is reported as not having arrived whole. A longer
body, or a missing, duplicate or malformed length, or chunked framing, is rejected
by name. The form value is decoded as ordinary URL-form data ('+' is a space)
and every character is kept, so inserted whitespace makes `parse_psbt_base64`
reject the text instead of being silently dropped; a second field is refused.
PSBTs larger than one packet cannot be reviewed yet. `tests/review.soma` checks the BIP 143 example's review,
the fee (known, unavailable, negative) and address cases, number formatting, the complete response head byte for byte, and the
served pages for raw HTTP requests. `tests/test_ui_http.py` boots `main.hvt`
host-only and isolated (as `scripts/run` does) and checks over HTTP the HTML
content type and length, the form and disabled actions, the fixture's review, a
typed rejection, a late body and a short-but-valid-prefix body reported as not
arriving whole, and whitespace inside the Base64 rejected.

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
The operation described below now connects this primitive to PSBT preparation
and approval for one selected input. UI signing and signed-PSBT export remain
unavailable.

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
Authoritative key/session ownership, secure key entry, session/UI integration
and persistence remain unavailable. A separate retained-slot adapter is described
below. The signer-side PSBT operation
below adds no browser or HTTP key/signing endpoint.


## Approved signing operation with pending-state hook

`wallet_sign_runtime.soma` now connects exact-content PSBT preparation, fresh
approval, runtime testnet/regtest WIF validation and key matching to bridge
signing and public signed-PSBT export for one native P2WPKH SIGHASH_ALL input.
The bridge verifies each produced signature with libsecp256k1. The adapter
re-reads and compares its compressed public key after signing, bounds/reads DER,
inserts the partial signature, re-parses the PSBT and completes Signed with a
reference bound to the original reviewed PSBT. Only public bytes/Base64 and the
next state are returned; errors contain no signed output, WIF or decoded key.
Bridge inputs and public outputs are cleared on success and every error.

`sign_reviewed_wif` is an IO operation taking a trusted `store_pending` callback.
After the pure approval check, it invokes this callback with the consumed-consent
Signing state **before any key/bridge IO, including cleanup**. The callback must
install that state in its single authoritative owner and return true only after
saving it. False prevents signing and returns a typed error with bridge cleanup.
Authorized validation failures return Signing, so the returned state refuses a
retry without a new load/review/approval. The caller must install final states on
success and failure, serialize events and never replay old immutable Approved
values. A dishonest/no-op callback cannot enforce this ownership contract.

This is an operation foundation, not the authoritative session/key store. WIF
must enter inside the signer only. WASM cleanup cannot erase immutable WIF/scalar
copies in the runtime. Handle-based PSBT composition, authoritative erase-on-lock,
multi-input signing, HTTP/UI import/approve/sign/export wiring and encrypted persistence remain
unavailable. The served sign button remains disabled; nothing is broadcast.

New `tests/sign_driver_fixture.json` contains an offline synthetic regtest
transaction: public scalar one owns a 100000-sat P2WPKH funding output and scalar
two's destination receives 99000 sat (1000-sat fee). The included funding
transaction is synthetic, not mined; its hash matches the signed outpoint.
Unknown PSBT entries check preservation. No network or real funds are involved.
The scalar-one WIF comes from `tests/keys.soma`; the wrong scalar-two WIF is also
public test data. Framing and digest follow BIP 174 and BIP 143.

`tests/runtime_sign_driver.soma` records the offered Signing state in an
instrumented hook while prior bridge staging is still dirty, proving callback
ordering. This test recorder is not a production state store. The boot checks
missing/reloaded/consumed approval, failed state storage, wrong key, substituted
metadata and malformed WIF, with no output and empty staging/output on rejection;
authorized failures and completed signatures cannot be signed a second time.
The exported PSBT parses and serializes to identical bytes. The new Python boot
check independently parses maps/transaction/funding, recomputes ownership/digest,
outputs/fee, checks only the partial signature was added and verifies DER with
Node/OpenSSL plus low-S and altered-signature/digest negatives. It checks WIF and
scalar hex are absent from logs. These checks run under `./scripts/check`.


## Retained signer-local test-key slot

`crypto/key_slot.c` adds one volatile key slot in a separate import-free WASM
module built from the same pinned libsecp256k1. The existing `crypto/signer.c`
module and all its APIs remain unchanged. `wallet_key_slot.soma` provides typed
runtime testnet/regtest WIF import, public identity, handle-based signature and
explicit lock operations. These are signer-internal primitives, not a session
owner, approval capability, browser endpoint or persistence mechanism. Use only
the documented public test keys in this development build.

`import_slot_wif` locks/invalidates the old slot before bounded WIF decoding. A
successful import validates the scalar with libsecp256k1, derives its compressed
public key, stores the scalar inside WASM and returns only `SlotIdentity` (a
numeric generation handle plus public network/key/hash/address). A failed WIF,
malformed scalar, incomplete import or invalid replacement cannot leave an older
key usable. The bridge has no retained or staged private-key byte reader.

Every bridge import attempt reserves a new generation in 1..65535, including
failed attempts. Import/replacement invalidates earlier handles immediately.
Lock wipes the retained scalar, transient key/digest staging, workspace and all
public outputs; it does not reset the generation counter. After generation
65535, further import attempts erase the slot and fail permanently for that WASM
instance. No generation wraps or is reused. Handles are internal identities,
not secrets or consent; they are valid only within their original running
instance and must all be abandoned on restart. The adapter rejects oversized
binary N handles before the numeric WASM ABI could narrow them into valid ones.

`sign_slot` takes that identity and an exact 32-byte digest, stages no key, and
signs inside WASM using the retained scalar. It returns public key/DER only after
libsecp256k1 verifies the signature against that digest. The Soma adapter checks
the returned public key against the imported identity and clears transient inputs
and public outputs before returning. Each digest staging is consumed; the key is
retained until explicit `lock_key_slot`, replacement or a fatal crypto/import
error. Invalid/stale handles produce no signature and clear staging/output.
Neither successful key custody nor a valid handle authorizes a transaction: a
future authoritative session driver must still validate ownership and exact PSBT
content, obtain fresh review approval and save its consumed state before crypto.

The legacy `clear_key_bridge` clears the legacy bridge; it does not lock this
separate retained slot. The future owner must call `lock_key_slot` on its lock and
reset events. These events are not wired to the served page or session model yet.
WASM erasure also cannot erase immutable WIF/scalar copies in Soma/OCaml; this
patch makes no stronger secret-memory lifecycle claim. `sign_reviewed_wif` still
uses the earlier per-call WIF path. Handle-based PSBT composition, authoritative
session ownership, UI signing, secure key entry and persistence remain unavailable.

New `tests/key-slot-check.mjs` verifies public scalar-one/two identities and DER
signatures with independent Node/OpenSSL, including changed-message/signature and
low-S checks. It exercises key replacement, lock, stale/missing handles, invalid
scalars, malformed/incomplete imports and digest staging. It exhausts the actual
65535-generation space without a test-only counter setter and proves lock cannot
reset it. Boolean bridge audits check staging/workspace clearing and lock erasure
of the retained scalar/output, without returning secret bytes.
`tests/key_slot_runtime.soma` and `test_key_slot_runtime.py` import a public WIF
selected at runtime, sign via its handle, verify the exported DER independently,
check the public regtest identity, replacement/lock invalidation, rejected
mainnet/malformed WIFs, and oversized-handle rejection before ABI narrowing.
Captured boot logs are checked for WIF/private scalar hex. The new tests run with
the unchanged legacy tests in `./scripts/check`. Nothing is broadcast or persisted.

## Serialized signer owner (command loop; UI still disabled)

`wallet_sign_owner.soma` adds `run_sign_owner`, a single application entry point
using the installed `Sandbox.iterate` state loop; it needs no mutable cell.
The command source receives
only its own input cursor. Commands import a signer-side regtest WIF, load public
PSBT bytes, approve the current review, request signing by input index, export,
lock/reset or stop. Neither commands nor emitted events accept or reveal a
session snapshot, key handle or permission. The event sink receives public
identity/review data, typed failures and public signed exports. Start exactly
one owner for the key-slot WASM instance and route all operations through it;
other wallet code must not call the slot directly or start concurrent owners.
This is application ownership within that entry point, not isolation against
malicious wallet code with access to the lower-level primitives.

For a sign command the owner consumes approval and returns a pending `Signing`
state to `iterate`. It retains only that permission and a prepared public digest,
not the old `Approved` value. The next loop step completes this work before
polling another command. Only that step calls `sign_slot`, verifies the slot's
public identity, inserts DER and installs the source-bound `Signed` result.
There is no caller-supplied pending-store callback. Preparation and signing
failures install the consumed state and clear staging/outputs. Import failures,
lock/reset and stop erase the slot and drop identity, review and export
references. Every load, including the same bytes or a malformed PSBT, invalidates
approval and old exports. A new load after signing begins a new review using
the retained identity; it needs another explicit approval command. The owner
cannot accept a mismatched caller key reference or sign caller-substituted PSBT
bytes: those are not sign-command parameters.

`tests/runtime_sign_owner.soma` boots a command stream against the live loop.
It imports public scalar one once before the successful signature, then tests
reload/consumption/repetition, invalid input index, a different PSBT, malformed
loads, scalar-two ownership failure, replacement failures, lock/reset and
export invalidation. The observer dirties staging after approval; the pending
event must precede slot cleanup/signing, and all other events require clean
staging/outputs. `tests/test_runtime_sign_owner.py` checks the exact public event
sequence and independently checks the exported maps, funding ownership, outputs,
1000-satoshi fee, BIP143 digest and low-S OpenSSL signature. Logs are checked for
both public fixture WIFs and scalar hex. Existing tests are unchanged.

The source and observer are trusted application callbacks; future transport
code must serialize genuine user review/approval events into this entry point.
There is no HTTP/UI command transport or secure signer-side key-entry flow yet,
and the served UI remains locked. WASM wiping does not erase immutable WIF
strings held by callers or runtime copies. Production vault unlock, persistence,
entropy checks and multi-input orchestration remain separate work.

## Handle-only approved PSBT signing (composition; not an authoritative owner)

`wallet_slot_sign_runtime.soma` signs an approved PSBT with the retained key
slot. The key is imported once, through `import_slot_wif`. `sign_reviewed_slot`
takes a `slot_identity` and never asks for, decodes or derives a WIF.
`slot_session` starts a session whose `key_ref` is the live slot generation.
After the pending state is saved, the composition does these steps in order:

- It refuses any session whose key reference does not name the given identity
  (`SlotPsbtKeyRefMismatch`).
- It prepares the exact approved PSBT and its BIP 143 digest, with ownership
  checked against the slot's public identity.
- It signs by handle (`sign_slot`), inserts the libsecp256k1-verified DER and
  completes `Signed`, bound to the source PSBT.

The existing `store_pending` hook runs before any slot IO. Every attempt that
reaches the hook consumes the approval. Every exit clears slot staging and
public outputs, but the retained key stays. `lock_slot_session` erases the
slot and returns `Locked`, which drops every handle, approval and export
reference. After a lock or a replacement import, old handles are refused as
stale.

What enforces what:

- The WASM slot enforces that only the current generation signs and that
  lock/replacement erase key material.
- The session transitions enforce approval, one-shot consumption and PSBT
  binding.
- The caller still threads the single session value, must install every
  returned state and must not replay old immutable states. `store_pending`
  remains a trusted callback contract.

This is a composition, not the authoritative owner. That owner is not
implemented in this step. No capability audit has been done, so the existing
Sandbox iteration and state-threading capabilities are not ruled out for it.
The owner and the HTTP/UI review, approve, sign, export and lock wiring remain
unavailable.

Identity generations are range-checked (1..65535) before any conversion to a
session key reference. Out-of-range identities are refused as
`SlotPsbtInvalidIdentity` before the hook or any slot IO, leaving the approval
untouched and staging clean. `slot_session` returns `None` for them.
WASM erasure does not cover the immutable WIF text the importer was given.

`tests/runtime_slot_sign.soma` and `tests/test_runtime_slot_sign.py` boot the
public fixture with scalar one, imported once. They cover these negatives:

- missing, reloaded and consumed approval
- a foreign key reference
- out-of-range identities: zero, 65536, and 2^32 above the live handle
- a different PSBT
- a failed pending store
- a repeated sign after `Signed`
- stale handles after lock, and after replacement by scalar two
- a replacement identity against the old approval

Each negative checks that slot staging and outputs are clean afterwards. The
Python check then verifies the exported PSBT independently: map preservation,
outputs and fee, funding ownership, the BIP 143 digest, and the OpenSSL
signature with low-S. It also checks that no WIF or scalar hex appears in the
logs.

## Owner request context and review revisions (transport prerequisite)

`wallet_owner_context.soma` adds `run_owner_context fixture_enabled next input emit`
for the UI's future command transport. It uses the merged owner's command and
pending-work functions, with **one** serialized owner state. It leaves
`run_sign_owner` and all existing APIs/tests unchanged. Do not run these two
entry points concurrently or access the key slot outside the selected owner.

The command source receives its own cursor and an `owner_public_view`: a binary
revision, public stage/identity, the existing complete transaction review, and
approve/sign/export availability. It never receives a session, permission,
slot identity/handle, key, or private owner snapshot. `UiOwnerRequest` attaches
a public request ID to each command. That ID is retained for pending, completion,
rejection and final view events, including the two signing iterations.
`UiOwnerView` is emitted on the iteration **after** the resulting state has been
installed. Pending signing finishes before a stable view or another request;
the loop retains no old Approved snapshot. A transport should render/respond
from this stable view, rather than infer state from an intermediate event.

`UiApproveRevision` must name the exact revision shown with the current loaded
review. The gate checks equality and requires the state to still be unapproved
`PsbtLoaded`. Every accepted mutation advances the binary revision, including
same-byte reloads, malformed loads, key replacement, lock/reset, approval and
sign attempts. Inspection/export do not advance it. Rejected stale approvals
also do not advance it. Revisions never reset on lock or narrow to a numeric
ABI; the old form cannot approve an identical later load or refresh an already
approved review. `UiSignInput` range-checks its binary index (0..63) before unary
conversion. Core ownership/signature policy still rejects unsupported or
not-owned inputs. All context rejections and inspection clear transient WASM
staging/outputs, and cleanup failure erases the owner rather than reporting
success. WASM erasure does not erase immutable secret copies held by callers.

This boundary accepts no WIF/scalar command. `UiImportPublicFixture` can import
only the existing **documented public scalar-one regtest test fixture**, and
only when the application supplied `fixture_enabled=true` at boot. The default
future application must pass false unless explicitly opted in; the flag is not
a request parameter. This is fixture development plumbing, not secure key entry.
Request IDs and revisions are public correlation/freshness data, not user
identity, authorization, CSRF protection, or cross-restart freshness tokens.
A future listener must validate complete, bounded HTTP framing before dispatch,
and authenticate/serialize genuine user consent. No listener is added here.

New `tests/owner_context.soma/.exp` check decoding, view availability, disabled
fixture import, stale/missing review, revision increments and huge-index rejection.
`tests/runtime_owner_context.soma` drives a single live owner by public commands,
checking its actual views/revisions through approval, identical reload, replay,
signing, repeated signing, export, replacement, lock/reset and malformed loads.
It dirties transient staging before each command and checks cleanup before the
next view/request. The Python test checks exact request correlation/event order,
fixture-disabled boot mode, log hygiene, and independently verifies the public
signed PSBT's maps, fee/funding/ownership, BIP143 digest, low-S and OpenSSL signature.
The fixture images are built by the full pinned `./scripts/check`; to run the
live fixture check after a build, use `python3 tests/test_owner_context.py`.

This is an explicitly partial UI step. `main.soma` still serves the existing
locked/read-only JSX page. HTTP framing/dispatch, revision-bearing forms, live
controls and downloads, fixture opt-in application bootstrap, browser verification,
secure signer-side key entry, multi-input orchestration, vault/persistence and
packaging remain unconnected. No unavailable UI action is presented as working.

## Typed SWVP adapter (KDF gate closed)

`wallet_vault_prod.soma` is the typed boundary over the SWVP exports.

`seal_input_error` and `open_input_error` are pure checks, and each length is
bounded before it is traversed:

- passphrase: 1..128 octets
- secret: exactly 32 octets
- salt and nonce: the format's exact-field and octet checks

Octets are checked to be below 256 before any numeric ABI call, so large binary
N values never narrow into valid bytes. Envelopes must parse through
`wallet_vault_format.soma` and re-serialize to the same bytes. That rejects SWVT,
truncated and trailing envelopes, bad octets, and weak or unknown KDF policies
before any KDF.

The normal entry points are `seal_production` and `open_production`. Every exit
evaluates its result and then calls the global `vault_lock`, which clears both
SWVT and SWVP staging, derived values and outputs. That includes pure format
errors, input-validation failures and the disabled path. A lock failure replaces
the result.

Booted Argon2id at the SWVP profile has not completed within 240 s (see above),
so `production_kdf_enabled` is `false`. Valid inputs return `ProdKdfUnavailable`
without staging secrets or running the KDF. They never return success,
plaintext or an SWVT substitute. Status of each piece:

- Typed validation and the fail-closed gates are live.
- Production seal and open through Soma are unavailable.
- The WASM primitives are verified on the host by `tests/vault-prod-check.mjs`.
- The staging, seal and open code behind the gate has not been exercised booted.

`vault_lock` erases WASM memory only. Passphrase and secret lists passed in by
callers, and any future opened secret returned to Soma, are immutable runtime
copies that it cannot erase.

Tests:

- `tests/vault_prod_codec.soma` with its `.exp` proves the pure codec and limit
  expectations: the closed gate, passphrase, secret, salt and nonce bounds,
  large-N octets, and SWVT, truncated, trailing, bad-octet and weak-memory
  envelopes.
- `tests/vault_prod_adapter.soma` with `tests/test_vault_prod_adapter.py` boots
  the adapter. Before every call it dirties both SWVT and SWVP staging. After
  each call it checks the typed rejection and that both audits and all four
  envelope/plaintext readers are clear. Cases cover malformed envelopes,
  oversized and large-N inputs, unknown policies and the disabled operations.

Salt and nonce stay caller-supplied. Entropy-sourced salt and nonce, key-slot
unlock, persistence and UI unlock remain unavailable. The vault protects and
persists nothing yet.
