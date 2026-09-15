# Claude Review Guidance

This repository contains RLN (RGB Lightning Node), a Rust daemon and SDK surface.

When reviewing pull requests, focus on:

- Correctness and regressions in channel lifecycle, payment state, and persistence.
- Safety around wallet/accounting invariants and RGB transfer state transitions.
- Error handling in daemon APIs and background tasks to avoid partial state writes.
- Security-sensitive boundaries (auth tokens, signing keys, network IO, serialization).
- Test coverage for behavior changes, especially around regtest and integration flows.

Repository conventions:

- Keep changes minimal and scoped to the PR goal.
- Prefer explicit errors over silent fallback behavior.
- Avoid introducing breaking API changes unless the PR explicitly requires it.
- Keep CI/workflow changes conservative and deterministic.

Minimal mobile SDK (`minimal-sdk/rust-sdk`, `minimal-sdk/android`, `minimal-sdk/apple`):

- A separate Cargo workspace with its own `Cargo.lock`; the root `cargo` commands do not
  build it. Test with `cargo test --manifest-path minimal-sdk/rust-sdk/Cargo.toml`;
  Android with `./minimal-sdk/android/gradlew -p minimal-sdk/android test assembleRelease`;
  Apple with `minimal-sdk/scripts/build_apple.sh` (macOS only) and
  `swift test --package-path minimal-sdk/apple`.
- Invariants to enforce in review: uniffi proc-macros only (no `.udl`); dependencies are
  `bitcoin`, `bip39`, `thiserror`, `uniffi` and nothing else (no `rgb-lib`, HTTP, TLS or
  async runtime; the release cdylib has a size gate in `tests/parity.rs`);
  `verify_and_sign_psbt` is the only signing entry point and runs `verify_psbt` first; no
  `SdkError` variant, `Debug` impl or log line may render a mnemonic, seed, xprv, private
  key or bearer token; every exported function returns `SdkResult` and no panic crosses
  the FFI, including from a foreign `HttpTransport` that throws.
- The parity fixture `minimal-sdk/packages/client-sdk/test/fixtures/rgblib-parity.json`
  is rgb-lib-authored ground truth: read by relative path, never copied or regenerated
  here. Changes to the mobile SDK must not touch `src/`, `bindings/` or
  `minimal-sdk/packages/`.
