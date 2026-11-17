# Wallet-only development scope

This repository is the sole governed source. Soma, Pantheon, Solo5 and all sibling
repositories are read-only dependencies. Do not modify them, install replacement
Soma versions, change their configurations, or expand this market's source scope.
Use Soma's existing Reason-style JSX (`Require Import JSX`) for the UI and its
existing Sandbox runtime for the MirageOS unikernel. Signing stays in the
unikernel; the browser never receives a private key, mnemonic, or decrypted vault.

This is an offline cold-storage signer development project. Use only public,
explicitly documented test keys and regtest/testnet fixtures. Do not use actual
user keys, contact Bitcoin mainnet services, broadcast transactions, or put
secrets in source, logs, URLs, cookies, browser storage, or generated artifacts.
The committed scalar-one secp probe is a public test fixture, never a wallet key.
The initial page is deliberately locked; do not present unavailable operations
as working. Do not write placeholder success responses for cryptographic work.

Use the pinned Bitcoin Core libsecp256k1 source through the app-local WASM wrapper.
Never replace it with handwritten elliptic-curve crypto. Its vendored source is
read-only; extend the wrapper and typed `.definition` in this repository.
Application PSBT parsing, sighashes, validation, address encoding and vault
integration need executable known-vector and negative tests. Document any
unsupported format and reject it explicitly. Do not claim production security.

Run `./scripts/check` from the exact checkout in the request. It builds and boots
real unikernels through the installed Soma toolchain. Mirage extraction/builds
share a host cache, so all builds must hold the existing `/private/tmp/soma-wallet-build.lock`
(the check script does). Do not run independent `soma build` processes beside it.
If you need a manual build, take that same file lock first. Use `opam exec
--switch=hvf -- soma ...` with `SOMA_MIRAGE_SWITCH=hvf`.

Keep work within the requested task. Do not start more Pantheon nodes, agent
sessions, or cloud jobs. Follow the diplomat inbox protocol for bids; do not
commit or push a bid's scratch checkout. Do not modify the network, its keys,
the host CI adapter, this file, the fixed CI entry point, or sibling repositories.
