# Minimal SDK for mobile: one Rust core, Kotlin and Swift bindings

## Overview

`docs/design/mobile-sdk-and-lightweight-uniffi.md` reaches one conclusion for mobile: **for
most apps the Minimal SDK variant is the answer, not a node on the phone.** The uniffi node CI
ships is 99.0 MB unstripped and carries the whole axum REST daemon; the TypeScript client SDK
that does the same user-facing job is 185.5 KB.

The design doc offered two mobile routes for that client — Path A2 (native Kotlin) and Path A3
(native Swift) — and costed each at "weeks of work", separately. This plan takes a third route
the doc did not cost: **one small Rust crate, exposed to both Kotlin and Swift through uniffi.**

The reason the doc did not consider it is that it compared Kotlin against *the node* (28×–52×
smaller) rather than against a *minimal Rust crate*. Measured on 2026-09-15 (method in
"Verified facts" below), a minimal Rust client crate with the real derive/PSBT/sign paths
reachable is **1.94 MB with uniffi scaffolding included, across 31 crates** — the same order as
the doc's ≈1.9 MB estimate for pure Kotlin, because both are dominated by the *same*
libsecp256k1 precomputed tables. With size neutral, the deciding factor becomes how many times
we implement the code that guards user funds.

So: **one implementation of keys, derivation, verify-before-sign, signing, invoice decoding and
intent binding**, in Rust, serving Android and iOS. Path A3 stops being a second project and
becomes a build target.

**This is not the node.** No LDK, no rgb-lib, no axum, no sea-orm, no chain backend. The crate
depends on `bitcoin`, `bip39` and `uniffi` and nothing else.

**Out of scope:** any change to the uniffi *node* or its build profile (Block 2 of the design
doc — a separate plan); any Rust change inside `rgb-lightning-node`; any gateway/server change;
replacing the TypeScript SDK; publishing to Maven Central or the Swift package registry; and
extraction of `minimal-sdk/` into its own repository.

## Context

- Authority for architecture and the size argument: `docs/design/mobile-sdk-and-lightweight-uniffi.md`
  (Block 1 Paths A2/A3, Block 3's mobile runtime constraints).
- Authority for the trust model, invariants I1–I4 and the five verify-before-sign checks:
  `docs/design/minimal-sdk-and-lightweight-rln.md`.
- The normative behavioural reference being ported: `minimal-sdk/packages/client-sdk/src/`
  (1,701 LOC across 8 files). The Rust crate must reproduce its behaviour, not its structure.

### Three design decisions that shape every task

1. **The Rust crate must NOT depend on `rgb-lib`.** Two reasons, both load-bearing. Size:
   rgb-lib is 12.5% of the node's `.text` and drags in sea-orm/sqlx — it would destroy the
   1.94 MB budget that justifies this approach. Correctness: the parity fixture is
   rgb-lib-generated, so if the client *were* rgb-lib's code, agreement would be tautological
   and a shared misreading of BIP-86 or the RGB coin types would be invisible. An independent
   implementation checked against rgb-lib's output is the property worth keeping.
2. **The TypeScript SDK stays hand-written and stays shipped.** It is 185.5 KB of pure JS;
   replacing it with wasm would be a large regression for web and React Native. The end state
   is therefore **two** implementations (TS + Rust) rather than three (TS + Kotlin + Swift) —
   this plan halves the duplication, it does not remove it, and the parity fixture is what
   keeps the two honest.
3. **HTTP transport is a foreign trait, everything else is Rust.** The crate defines a
   transport trait with `#[uniffi::export(with_foreign)]`; Kotlin implements it over OkHttp or
   `HttpURLConnection`, Swift over `URLSession`. Networking stays idiomatic and async-friendly
   per platform, Rust never links an HTTP stack or a TLS stack, and there is no async-over-FFI.
   **Intent binding stays in Rust** — it is security-critical logic, not plumbing.

### Verified facts (measured/re-verified 2026-09-15 on `dev`; re-check line numbers when citing)

**The size measurement that motivates this plan.** Scratch crate with `bitcoin` 0.32 +
`bip39` 2.2, release profile `opt-level="z"` + `lto="thin"` + `strip="symbols"` +
`codegen-units=1`, host `x86_64-unknown-linux-gnu`, with BIP-39→BIP-32→taproot-derive→PSBT-
parse→key-path-sign→serialize all reachable from exported symbols so LTO cannot strip them:

| Build | raw | gzip | crates |
| --- | --- | --- | --- |
| `bitcoin` + `bip39`, C-ABI exports | 1.89 MB | 1.42 MB | 30 |
| **+ uniffi scaffolding + exported fns** | **1.94 MB** | ~1.45 MB | 31 |
| Pure Kotlin (design doc, measured) | ≈1.9 MB | — | — |
| uniffi **node**, tuned / as CI ships | 46.6 / 99.0 MB | — | 769 |

- **uniffi scaffolding costs 48 KB** (1,981,992 → 2,030,936 bytes). It is not a size factor.
- **1.06 MB of the 1.94 MB is secp256k1 precomputed tables**, confirmed by symbol:
  `rustsecp256k1_v0_10_0_pre_g` 512 KB + `..._pre_g_128` 512 KB + `..._ecmult_gen_prec_table`
  64 KB. The design doc measured the same 1.12 MB of tables inside `secp256k1-kmp`'s `.so` —
  it is the same C library either way, so no Kotlin/Rust choice removes it.
- **Actual Rust code is 460 KB of `.text`.** The remaining delta versus pure Kotlin is JNA
  (below), not compiled code.
- ⚠️ **x86_64 host figures**, same caveat as the design doc's Appendix C. Re-measure on
  arm64 before quoting externally; Task 8 records the real arm64 number.

**The cost side, to keep the decision honest:**

- uniffi's Kotlin bindings require **JNA** — `net.java.dev.jna:jna:5.14.0@aar` is 518 KB, of
  which 293 KB is dead mips/mips64 slices Android dropped in NDK r17
  (`bindings/kotlin-android-sdk/build.gradle.kts`, design doc measurement). Pure Kotlin avoids
  it entirely (`secp256k1-kmp` uses direct JNI). Honest comparison: **≈2.46 MB (Rust+JNA) vs
  ≈1.9 MB (pure Kotlin)** on Android. Rust wins on implementation count, not on bytes.
- This plan **reintroduces the NDK and cross-compilation** that a pure-Kotlin SDK avoided. No
  NDK is installed on the development machine (`~/Android/Sdk/ndk` absent); Task 8 installs it.

**What is being ported** (`minimal-sdk/packages/client-sdk/src/`): `network.ts` 57,
`keys.ts` 90, `derive.ts` 117, `verify.ts` 383, `sign.ts` 91, `invoice.ts` 316, `gateway.ts` 566.

- **The five checks** (`verify.ts:50-59`, implemented at `:221`, `:331`, `:349`, `:358`, `:366`):
  `inputs-own`, `recipients-match`, `change-own`, `fee-budget`, `opret-zero`.
- **Two security properties that must survive the port**, both documented in the TS source as
  the reason the code is shaped the way it is:
  1. `matchOriginPath` (`derive.ts:85`) is the **single source of truth for path acceptance**,
     shared by verify (proving scripts) and `privateKeyForPath` (selecting signing keys). Two
     independent path-acceptance implementations can drift, and verify would then approve a
     path sign does not use.
  2. `ownDerivation` (`verify.ts:156`) selects the key-origin entry **by our master
     fingerprint, never by path shape**, and `sign.ts:64` signs with the very entry verify
     proved. Shape-matching alone lets a decoy entry carrying a foreign fingerprint, ordered
     first, divert signing to a key no check covered.
- **Own OUTPUTS are restricted to keychain 0 at a bounded index; own INPUTS are not**
  (`verify.ts:260-270`). Deliberate asymmetry — do not "tidy" it.
- **Check 2 re-derives the expected script from the human-readable address** and only
  cross-checks the server's `scriptHex` (`verify.ts:283-297`); otherwise a hostile gateway
  pairs the intended address with an attacker script and both "match".
- **Intent binding is what makes check 2 non-vacuous** (`gateway.ts:141-159`) — without it the
  client verifies the server's PSBT against the server's own intent.

**The parity fixture** — `minimal-sdk/packages/client-sdk/test/fixtures/rgblib-parity.json`,
generated from the real `@utexo/rgb-lib` binding: account xpubs + master fingerprint
(`73c5da0a`) for all four networks; 5 vanilla + 5 colored regtest addresses at indexes 0..4;
`signing.{unsignedPsbt,signedPsbt,txid,witnessSignature}`;
`witnessReceive.{invoice,recipientId,expirationTimestamp}`; the reference mnemonic and a
foreign one.

- **BIP-340 signatures are randomized**, so witness bytes are NOT comparable
  (`test/sign.test.ts:58-59` says so). The parity assertion is **same txid**, one 64-byte
  witness element, and the signature **verifies** against the re-derived x-only key.

**uniffi mechanics already proven in this repo — reuse, do not reinvent:**

- Foreign-implemented traits: `#[uniffi::export(with_foreign)] pub trait ExternalSignerHost`
  (`src/uniffi_api/mod.rs:32`). This is the model for the HTTP transport trait.
- **Library-mode binding generation** (no `.udl` to maintain):
  `scripts/ci/uniffi_generate_from_library.sh <kotlin|swift>` uses
  `uniffi-bindgen generate <lib> --library`. The new crate is proc-macro only — **do not add a
  UDL file**.
- Android cross-compilation: `scripts/ci/build_android_jni.sh` uses `cargo ndk -t <abi>` for
  arm64-v8a, armeabi-v7a, x86_64. Copy the shape; the aws-lc cleanup it does is node-specific
  and must NOT be carried over (this crate has no aws-lc).
- XCFramework packaging: `scripts/ci/package_swift_xcframework.sh` — `lipo` the simulator
  slices, then `xcodebuild -create-xcframework` over **static** `.a` plus headers.
- Gradle/publishing conventions: `bindings/kotlin-android-sdk/build.gradle.kts` (AGP 8.7.3,
  Kotlin 1.9.24, JDK 17, compileSdk 34, minSdk 24, `consumerProguardFiles`,
  `singleVariant("release")`). Copy the shape; drop the uniffi-node `srcDir`/`jniLibs` wiring
  and JReleaser (no publishing in this plan).

**Toolchain verified on the development machine:**

- Rust 1.98.0; all required crates present in the local registry cache (offline builds work).
- JDK **17.0.19 Temurin** at `~/.jdks/temurin-17` — **not on `PATH`**; set `JAVA_HOME`.
- Android SDK at `~/Android/Sdk`: platforms `android-34`/`android-35`, build-tools `34.0.0`,
  `cmdline-tools/latest`. **No NDK** — Task 8 installs one.
- `android-e2e` is on AGP 8.3.0 with a Gradle 8.7 wrapper. AGP 8.7.3 needs Gradle **≥ 8.9**, so
  the new Gradle project needs **its own wrapper**; do not reuse `android-e2e`'s.
- ⚠️ **No macOS host is available here.** Task 9 (Swift/XCFramework) cannot be built or
  verified locally — see "Development Approach".
- `minimal-sdk/pnpm-workspace.yaml` globs `packages/*` only, so new Cargo/Gradle directories
  under `minimal-sdk/` need no pnpm changes.

### Files involved

- Create (Rust): `minimal-sdk/rust-sdk/{Cargo.toml,Cargo.lock,README.md}`,
  `minimal-sdk/rust-sdk/src/{lib.rs,network.rs,keys.rs,derive.rs,verify.rs,sign.rs,invoice.rs,gateway.rs,ffi.rs}`,
  `minimal-sdk/rust-sdk/tests/parity.rs`
- Create (Android): `minimal-sdk/android/` — Gradle project, wrapper 8.9+, `build.gradle.kts`,
  `consumer-rules.pro`, `src/main/AndroidManifest.xml`, `src/test/kotlin/…SmokeTest.kt`
- Create (Apple): `minimal-sdk/apple/` — `Package.swift`, `Tests/…SmokeTests.swift`
- Create (scripts): `minimal-sdk/scripts/{build_android.sh,build_apple.sh,generate_bindings.sh}`
- Create (CI): `.github/workflows/minimal-sdk-mobile.yaml`
- Read-only, never modified: `minimal-sdk/packages/client-sdk/src/**`, the parity fixture,
  both design docs, everything under `src/` and `bindings/`
- Modify only in Task 11: `minimal-sdk/README.md`, `docs/design/mobile-sdk-and-lightweight-uniffi.md`

### Dependencies

`bitcoin` 0.32 (`std`, `rand-std`, `base64`; BIP-32, taproot, PSBT), `bip39` 2.2,
`uniffi` 0.28.3, `thiserror` 2.0. **Nothing else.** In particular: no `rgb-lib`, no `reqwest`,
no TLS stack, no `tokio`, no `serde_json` unless a task proves it cannot be avoided — every
addition is measured against the Task-1 size gate before it lands.

Build-time only: `uniffi-bindgen` (reuse `bindings/uniffi-bindgen/`), `cargo-ndk`, Android NDK,
and on CI macOS runners Xcode for the XCFramework.

## Development Approach

- **Testing approach**: Regular (code first, then tests). The Rust crate carries the **full**
  parity and adversarial suite (`cargo test`); the Kotlin and Swift sides carry **smoke** tests
  only — enough to prove the generated binding surface works end to end, not a third and fourth
  copy of the same assertions. This mirrors what the repo already does (`test/kotlin-e2e` is
  one file, the Swift job is a smoke).
- Gate command for Tasks 1–7: `cargo test --manifest-path minimal-sdk/rust-sdk/Cargo.toml`
- Gate command for Task 8: `JAVA_HOME=~/.jdks/temurin-17 ./gradlew -p minimal-sdk/android test`
- **⚠️ Task 9 is not locally runnable.** Building the XCFramework needs macOS + Xcode, which
  this machine does not have. The agent writes the script, the `Package.swift` and the CI job,
  and verifies everything that *is* checkable on Linux (bindings generate, Swift sources are
  produced, the packaging script passes `shellcheck`/`bash -n`). Actual XCFramework assembly
  and the Swift smoke test are verified by the macOS CI job in Task 10 and signed off in
  Post-Completion. Do not fake a local pass.
- **Parity rule, non-negotiable:** tests read
  `minimal-sdk/packages/client-sdk/test/fixtures/rgblib-parity.json` **by relative path**. Do
  not copy it, do not regenerate it, do not add a Rust fixture generator. One rgb-lib-authored
  ground truth, checked by an implementation that shares no code with it.
- **Port behaviour, not line shape.** Where the TS source explains *why* (fingerprint-based
  entry selection, the input/output asymmetry, address re-derivation in check 2), carry that
  reasoning into the Rust doc comment so the two implementations can be diffed on intent.
- **Invariants that must hold in every task** (design doc I1–I4):
  - the mnemonic and any xprv **never** leave the device and are never a gateway request field;
  - only account xpubs + master fingerprint are ever sent to the gateway;
  - nothing logs, `Debug`-prints or renders a mnemonic, seed, xprv or private key — including
    error variants, which is where this leaks in practice. Assert it in tests, and prefer
    manual `Debug` impls over `#[derive(Debug)]` on any type holding secrets.
- **No panics across the FFI boundary.** Every exported function returns `Result<_, SdkError>`;
  `verify` returns a failed verdict rather than an error for hostile input; no `unwrap()` or
  `expect()` on anything derived from caller or PSBT data. A panic here becomes a host-app
  crash.
- Signature assertions: **txid parity + signature validity**, never witness byte-equality.
- **Size discipline:** the Task-1 size gate runs in every subsequent task's test run. A task
  that pushes the crate over budget must justify it in the progress notes or drop the
  dependency that caused it.
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**

## Implementation Steps

### Task 1: Rust crate skeleton, uniffi scaffolding, parity harness and size gate

**Files:**
- Create: `minimal-sdk/rust-sdk/{Cargo.toml,src/lib.rs,src/ffi.rs,tests/parity.rs}`

- [ ] Create `minimal-sdk/rust-sdk` as its **own Cargo workspace** (`[workspace]` in its
      `Cargo.toml`, the pattern `bindings/c-ffi/Cargo.toml` uses) so it never pulls the
      rgb-lightning-node dependency graph. `crate-type = ["cdylib", "staticlib", "lib"]` —
      cdylib for Android, staticlib for the iOS XCFramework. Release profile
      `opt-level="z"`, `lto="thin"`, `strip="symbols"`, `codegen-units=1`,
      `panic="unwind"` (uniffi converts panics at the boundary; `panic="abort"` would turn a
      recoverable error into an app crash — the design doc records this trade at Block 2 item 9)
- [ ] Add `uniffi::setup_scaffolding!()` and one trivial exported function; confirm
      `scripts/ci/uniffi_generate_from_library.sh kotlin` and `… swift` both generate against
      the built library with **no UDL file present**
- [ ] Define the shared error type `SdkError` (`#[derive(uniffi::Error)]`) with variants that
      carry no key material, and the `SdkResult` alias every exported function returns
- [ ] Prove the parity harness: a test loading
      `../packages/client-sdk/test/fixtures/rgblib-parity.json` by relative path and asserting
      `masterFingerprint == "73c5da0a"` on Regtest. This pins the parity rule before any crypto
      exists
- [ ] **Size gate** (runs in every later task): build release, assert the stripped cdylib is
      under **2.5 MB**, and print the measured number. Baseline to compare against: 1.94 MB
      measured 2026-09-15 for `bitcoin` + `bip39` + uniffi. Budget rationale is in the Context
      section — 1.06 MB of it is secp256k1 tables and is irreducible
- [ ] Tests: the fixture-loading test, the size gate, and a dependency-creep guard asserting
      the resolved graph contains **no** `rgb-lib`, `reqwest`, `tokio`, `rustls` or
      `openssl` crate
- [ ] Run `cargo test --manifest-path minimal-sdk/rust-sdk/Cargo.toml` — must pass before Task 2

### Task 2: Network constants and key management (BIP-39 → BIP-32 accounts)

**Files:**
- Create: `src/network.rs`, `src/keys.rs`; extend `tests/parity.rs`

- [ ] Port `network.ts` behaviour: `BitcoinNetwork` enum, `PURPOSE = 86`, `ACCOUNT = 0`,
      `KEYCHAIN = 0`, RGB coin types **827166** (mainnet) / **827167** (everything else),
      xprv/xpub vs tprv/tpub version bytes, per-network address HRP (`bc`/`tb`/`tb`/`bcrt`);
      `account_path(network, colored)` returns `[86', coin', 0']`
- [ ] Port `keys.ts` as `ClientKeys`: `generate(network)` (fresh 12-word mnemonic) and
      `from_mnemonic(mnemonic, network)` returning `SdkError::InvalidMnemonic` on a bad
      checksum; BIP-39 seed with an **empty passphrase**; vanilla + colored account keys;
      expose `fingerprint` (8 lowercase hex chars) and `xpubs` (**public material only**)
- [ ] Add `private_key_for_path(path)` returning `None` (never an error, never a panic) for
      foreign paths, delegating to the shared `match_origin_path` landing in Task 3 — leave a
      TODO only if Task 3 has not landed, and close it there
- [ ] Secrets hygiene: `ClientKeys` must not expose the mnemonic, seed or any xprv; write a
      **manual `Debug` impl** that renders no secret; no secret may reach an `SdkError` variant
- [ ] Tests: for **all four networks**, assert `accountXpubVanilla`, `accountXpubColored` and
      `masterFingerprint` equal the fixture exactly; a bad-checksum mnemonic is rejected; the
      fixture's `otherMnemonic` yields different xpubs; `generate()` round-trips through
      `from_mnemonic`; `format!("{:?}", keys)` contains neither the mnemonic nor `xprv`/`tprv`
- [ ] Run the gate — must pass before Task 3

### Task 3: Taproot derivation and origin-path matching

**Files:**
- Create: `src/derive.rs`; modify `src/keys.rs`; extend `tests/parity.rs`

- [ ] Port `derive_taproot(account_xpub, keychain, index, network)`: derive the child key, take
      the x-only internal key, build the BIP-341 `tr(key)` output script and the bech32m
      address, return script hex + address + internal-key hex
- [ ] Port `match_origin_path(path, network)` as the **single source of truth for path
      acceptance**: accepts only `[86', coin', 0', keychain, index]` under one of the two
      accounts, rejects hardened keychain/index, returns `None` (never an error) on foreign
      paths — it is fed attacker-controlled PSBT metadata
- [ ] Port `derive_for_origin_path` returning `None` when the path is not ours or derivation fails
- [ ] Wire `ClientKeys::private_key_for_path` to `match_origin_path`, with a comment stating
      that what verify proves is exactly what sign derives
- [ ] Tests: the 5 `regtest.vanillaAddresses` and 5 `regtest.coloredAddresses` are reproduced
      exactly at keychain 0, indexes 0..4; `match_origin_path` accepts both accounts and
      rejects wrong purpose/coin/account, hardened keychain or index, and short and over-long
      paths — returning `None` in every case rather than erroring; `private_key_for_path`
      returns a key for exactly the paths `match_origin_path` accepts
- [ ] Run the gate — must pass before Task 4

### Task 4: Verify-before-sign — the five checks

**Files:**
- Create: `src/verify.rs`; extend `tests/parity.rs`

> No PSBT-codec task: `bitcoin::psbt::Psbt` already parses and re-serializes the taproot fields
> this SDK needs — verified 2026-09-15 by round-tripping the fixture PSBT through
> `Psbt::deserialize`, reading `tap_key_origins` / `tap_internal_key` / `witness_utxo`, signing
> and re-serializing. The first checkbox re-confirms the one property that matters.

- [ ] **Confirm before building on it:** `Psbt::deserialize` preserves **every**
      `tap_key_origins` entry, including a foreign-fingerprint entry alongside ours on the same
      input. `tap_key_origins` is keyed by x-only pubkey, so distinct decoy keys should survive
      — prove it with a test rather than assuming, because the decoy defence depends on it
- [ ] Port the intent types (`OnchainIntent`, `IntentRecipient`, `IntentAsset`, `IntentUtxos`)
      and the verdict types (`CheckName`, `CheckResult`, `VerifyVerdict`) with the same five
      check names: `inputs-own`, `recipients-match`, `change-own`, `fee-budget`, `opret-zero`
- [ ] Port `own_derivation`: select the key-origin entry **by our master fingerprint**, never by
      path shape; expose it for Task 5 to reuse; carry the reasoning into the doc comment
- [ ] **Check 1 (`inputs-own`)** — every input has a `witness_utxo`, a key origin with our
      fingerprint, a path re-deriving from **our** xpubs to the **exact** script being spent,
      and (when present) a matching `tap_internal_key`; zero inputs fails
- [ ] **Check 2 (`recipients-match`)** — re-derive the expected script **from the recipient
      address**, cross-check the intent's `scriptHex` against it, then match recipients against
      outputs as a **multiset** (each output consumed at most once); for witness asset sends
      require **exactly one** unaccounted, non-own, non-OP_RETURN output at exactly the
      approved `witnessAmountSat`
- [ ] **Check 3 (`change-own`)** — every output that is not an accounted recipient, the
      approved witness output, or an OP_RETURN must prove ownership. Preserve the asymmetry:
      own **outputs** must be keychain 0 at a bounded index; own **inputs** are unrestricted.
      Keep the lazy scan-window fallback for metadata-less change, derived only on demand
- [ ] **Check 4 (`fee-budget`)** — `fee = inputs − outputs`, ok only when `0 < fee ≤ max_fee_sat`
- [ ] **Check 5 (`opret-zero`)** — every OP_RETURN output carries 0 sats
- [ ] `verify_psbt` must **never** return an error and never panic: any parse or derivation
      failure yields a verdict with **all five** checks failed and the reason in `detail`
- [ ] Tests, each asserting the *specific* check that fails: happy path on
      `signing.unsignedPsbt` passes all five; a foreign input (fingerprint from
      `otherMnemonic`) fails only `inputs-own`; a tampered recipient amount and a tampered
      recipient address each fail only `recipients-match`; an intent whose `scriptHex`
      contradicts its own address fails `recipients-match`; an unaccounted foreign output fails
      only `change-own`; an own-looking output at keychain 1 or beyond the index bound fails
      `change-own`; a fee above budget and a negative fee each fail only `fee-budget`; a funded
      OP_RETURN fails only `opret-zero`; **the decoy test** — a foreign-fingerprint key-origin
      entry present alongside ours must not divert selection; truncated and garbage PSBT bytes
      return all-five-failed with no panic and no `Err`
- [ ] Run the gate — must pass before Task 5

### Task 5: Sign and finalize

**Files:**
- Create: `src/sign.rs`; extend `tests/parity.rs`

- [ ] Port `verify_and_sign_psbt(keys, psbt_base64, params)`: run `verify_psbt` **inside** this
      function and return `SdkError::VerificationFailed` (carrying the failed check names) when
      the verdict is not ok. There must be **no** exported entry point that signs without
      verifying — no flag, no second function, no `pub` helper that skips it
- [ ] For each input, select the signing entry with `own_derivation` using our fingerprint —
      **the same entry check 1 proved** — then derive via `private_key_for_path`; a missing key
      is an error naming the input index, never a skip
- [ ] BIP-341 key-path sign every input, set `tap_key_sig`, finalize into
      `final_script_witness`, and return the base64 signed+finalized PSBT, the txid and the verdict
- [ ] Tests: sign `signing.unsignedPsbt` and assert (a) the verdict is ok, (b) the txid equals
      `signing.txid`, (c) exactly one 64-byte witness element, (d) **the signature verifies** as
      BIP-340 over the BIP-341 sighash against the re-derived x-only key, and (e) rgb-lib's own
      `signing.signedPsbt` parses to the same txid. **Do not** assert witness byte-equality
      against `signing.witnessSignature` — BIP-340 signatures are randomized
- [ ] Tests (refusal paths): a tampered recipient amount returns `VerificationFailed` and
      produces **no** signature; an input whose key-origin path is not ours errors; no error
      message contains key material
- [ ] Run the gate — must pass before Task 6

### Task 6: Invoice decoding (BOLT-11 and RGB)

**Files:**
- Create: `src/invoice.rs`; extend `tests/parity.rs`

- [ ] Port `decode_bolt11`: bech32 decode with the length limit disabled, HRP → network and
      amount (`m`/`u`/`n`/`p` multipliers over msat-per-BTC), tagged-field parsing, payee
      recovery from the signature. Malformed input returns `SdkError::InvoiceDecode` — never a
      panic; this is fed user-pasted strings
- [ ] Port `decode_rgb_invoice`, including the `~` omitted-field convention
- [ ] Prefer `bitcoin`'s existing bech32 and secp256k1 recovery over new dependencies; if a
      dependency is genuinely required, record the size-gate delta in the progress notes
- [ ] Tests: decode `witnessReceive.invoice` and assert `recipientId` and
      `expirationTimestamp` match the fixture; port the BOLT-11 vectors from
      `packages/client-sdk/test/invoice.test.ts` — they are the reference — covering network,
      amount (including a no-amount invoice), payment hash and recovered payee; malformed,
      truncated and wrong-checksum input each return `InvoiceDecode` and nothing else
- [ ] Run the gate — must pass before Task 7

### Task 7: Gateway client, foreign HTTP transport, and intent binding

**Files:**
- Create: `src/gateway.rs`; extend `tests/parity.rs`

- [ ] Define the transport seam with `#[uniffi::export(with_foreign)] pub trait HttpTransport:
      Send + Sync`, taking a request (method, path, headers, optional body) and returning a
      response (status, body) or an error — modelled on `ExternalSignerHost`
      (`src/uniffi_api/mod.rs:32`). Rust performs **no** network IO and links **no** HTTP or
      TLS stack; the host supplies OkHttp/`URLSession`. The call is synchronous from Rust's
      side, so there is no async-over-FFI
- [ ] Port `GatewayClient` over all **22** routes: `/v1/users`, `/v1/me`, `/v1/wallet/{xpubs,
      address,balances,unspents,transfers,receive,sync}`, `/v1/onchain/{send-btc,send-asset,
      create-utxos}/{prepare,complete}`, `/v1/ln/{deposit/prepare,pay,invoice,invoice/{hash},
      payments,balance,withdraw}`; bearer-token auth; an error carrying status and body
- [ ] Port **intent binding** for the three `prepare*` methods — the security core of this
      task, not boilerplate. Assert every field the caller actually stated (recipient address
      and amount, asset id/amount/recipient id, utxo shape), assert the shape negatives (no
      asset on a send-btc intent, no recipients on an asset/utxo intent), assert caller-pinned
      optional fields only when pinned, and return an error listing every mismatch. Carry over
      the comment explaining that check 2 is vacuous without this
- [ ] Port idempotency-key generation as RFC-4122 v4 from a **cryptographic** RNG (`bitcoin`
      already pulls `rand`; do not add a dependency), sent on the money-moving routes exactly
      where the TS client sends it
- [ ] Secrets hygiene: assert in a test that no request body or header any method produces
      contains the mnemonic, a seed or an `xprv`/`tprv`, and that the bearer token never
      appears in an error message or `Debug` output
- [ ] Tests against a fake in-Rust `HttpTransport` (no network): one round-trip per route
      asserting method, path, auth header and body shape; intent-mismatch errors for a swapped
      recipient address, a changed amount, an asset smuggled onto a send-btc intent, an extra
      recipient, and a foreign `witnessAmountSat`; status and body surface on 4xx/5xx;
      idempotency keys are unique across calls and stable when supplied by the caller
- [ ] Run the gate — must pass before Task 8

### Task 8: Android packaging — bindings, JNI libs, AAR, 16 KB alignment

**Files:**
- Create: `minimal-sdk/scripts/{generate_bindings.sh,build_android.sh}`,
  `minimal-sdk/android/` (Gradle project, wrapper 8.9+, `build.gradle.kts`,
  `consumer-rules.pro`, `src/main/AndroidManifest.xml`,
  `src/test/kotlin/com/utexo/minimalsdk/SmokeTest.kt`)

- [ ] Install an NDK via `sdkmanager` (none is present) and add `build_android.sh` modelled on
      `scripts/ci/build_android_jni.sh`: `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64`.
      **Do not** copy that script's aws-lc cleanup — this crate has no aws-lc
- [ ] `generate_bindings.sh kotlin` wraps `uniffi-bindgen … --library` against the built
      cdylib (library mode, no UDL), writing generated Kotlin into the Gradle source set
- [ ] Gradle project: `com.android.library`, AGP 8.7.3, Kotlin 1.9.24, JDK 17,
      `compileSdk = 34`, `minSdk = 24`, namespace `com.utexo.minimalsdk`, **its own wrapper at
      Gradle 8.9+**. Depends on JNA (uniffi requires it) and nothing else. ABI splits on, so a
      consumer downloads one `.so`
- [ ] **16 KB page-alignment check** on every produced `.so`: assert each `PT_LOAD` segment
      alignment is **≥ 16384**. Mandatory for native code on Android 15+ (extended deadline
      **2026-05-31, already passed**), and the design doc notes nothing in this repo has ever
      asserted it. A failure is a **release blocker** to record in the progress notes, with the
      linker flag or NDK version that fixes it — do not ship a misaligned `.so`
- [ ] **Android size gate**: record the real **arm64** `.so` size (the Context table's 1.94 MB
      is an x86_64 host figure) plus the AAR and JNA, and fail above **3.0 MB** for the single
      arm64 slice. Note in the README that install size tracks the **raw**, not compressed, number
- [ ] `consumer-rules.pro` keeps only what R8 must not strip — the uniffi/JNA entry points.
      **No** blanket `-keep class com.utexo.minimalsdk.** { *; }`
- [ ] Tests: a Kotlin **smoke** test through the generated bindings — restore from the fixture
      mnemonic, assert the Regtest account xpubs and fingerprint match the fixture, derive
      address index 0, and verify+sign the fixture PSBT to `signing.txid` using a Kotlin-side
      `HttpTransport` stub for construction. Deep assertions stay in Rust; this proves the
      binding surface, the JNI load and the `with_foreign` trait all work
- [ ] Run `JAVA_HOME=~/.jdks/temurin-17 ./gradlew -p minimal-sdk/android test` plus the
      alignment and size checks — must pass before Task 9

### Task 9: Apple packaging — bindings, static libs, XCFramework, SwiftPM

**Files:**
- Create: `minimal-sdk/scripts/build_apple.sh`, `minimal-sdk/apple/Package.swift`,
  `minimal-sdk/apple/Tests/MinimalSdkTests/SmokeTests.swift`

> **⚠️ Not verifiable on this machine.** XCFramework assembly needs macOS + Xcode. Write the
> scripts, the package manifest and the tests; verify on Linux everything that can be verified
> (Swift bindings generate from the built library, the scripts pass `bash -n`/`shellcheck`, the
> manifest is well-formed); mark the rest explicitly as CI-verified in Task 10 and human-signed
> in Post-Completion. **Do not claim a local pass.**

- [ ] `generate_bindings.sh swift` in library mode, producing the Swift sources, the
      `…FFI.h` header and the modulemap
- [ ] `build_apple.sh` modelled on `scripts/ci/package_swift_xcframework.sh`: build
      `--release` **staticlib** for `aarch64-apple-ios` and the simulator targets, `lipo` the
      simulator slices into one universal `.a`, then `xcodebuild -create-xcframework` with
      device + simulator libraries and the headers directory
- [ ] `Package.swift` exposing a `binaryTarget` over the XCFramework plus a Swift target
      carrying the generated bindings and a small `URLSession`-backed `HttpTransport`
      conformance; iOS deployment target consistent with `minSdk`-equivalent policy and recorded
      in the README
- [ ] Swift **smoke** test mirroring the Kotlin one: restore from the fixture mnemonic, assert
      the Regtest xpubs/fingerprint, derive index 0, verify+sign the fixture PSBT to
      `signing.txid`
- [ ] Note in the README that iOS links statically and dead-strips at app link, so the number
      that matters is the **app-size delta**, not the `.a` size (the node's `.a` is 391.9 MB and
      that figure has misled before)
- [ ] Verify locally what is verifiable: Swift bindings generate with no UDL; `bash -n` and
      `shellcheck` pass on both scripts; `Package.swift` parses. Record in the progress notes
      exactly which steps were **not** run and why
- [ ] Do not proceed to Task 10 until the above local checks pass

### Task 10: CI for the mobile SDK

**Files:**
- Create: `.github/workflows/minimal-sdk-mobile.yaml`

- [ ] Workflow on push/PR **path-filtered** to `minimal-sdk/rust-sdk/**`,
      `minimal-sdk/android/**`, `minimal-sdk/apple/**`, `minimal-sdk/scripts/**`,
      `minimal-sdk/packages/client-sdk/test/fixtures/**` and the workflow file, plus
      `workflow_dispatch`. Pin every action version; cache the cargo registry and the Gradle
      user home
- [ ] Job 1 (ubuntu) — **the real gate**: `cargo test` for the Rust crate including the full
      parity/adversarial suite, the size gate and the dependency-creep guard. Fast, no NDK
- [ ] Job 2 (ubuntu) — Android: NDK, `cargo ndk` for three ABIs, generate Kotlin bindings,
      `./gradlew test`, the 16 KB alignment check, the arm64 size gate, `assembleRelease`
- [ ] Job 3 (**macos runner**) — Apple: Swift bindings, iOS + simulator static libs,
      XCFramework, Swift smoke test. This is the job that first proves Task 9
- [ ] The fixture path filter is deliberate: if `rgblib-parity.json` is regenerated the parity
      suite must re-run. Say so in a comment in the workflow
- [ ] Tests: run Jobs 1 and 2's exact commands locally and confirm each exits zero on a clean
      tree; then perturb one fixture value in the working tree, confirm the Rust parity suite
      fails, and restore it — the gate must actually catch drift. Job 3 is verified by its
      first CI run, not locally
- [ ] Run the local gates — must pass before Task 11

### Task 11: Verify acceptance criteria and update documentation

**Files:**
- Create: `minimal-sdk/rust-sdk/README.md`
- Modify: `minimal-sdk/README.md`, `docs/design/mobile-sdk-and-lightweight-uniffi.md`

- [ ] Full local gate green: `cargo test --manifest-path minimal-sdk/rust-sdk/Cargo.toml`,
      `JAVA_HOME=~/.jdks/temurin-17 ./gradlew -p minimal-sdk/android test assembleRelease`, and
      `pnpm -C minimal-sdk test` still green (this plan must not have touched the TS side —
      confirm with `git status`)
- [ ] Verify acceptance item by item and record the evidence: all four networks' xpubs +
      fingerprint match the fixture; all ten regtest addresses match; the fixture PSBT signs to
      `signing.txid` with a verifying signature; all five checks fail individually on their own
      tampering; the decoy test passes; intent binding fires on all five tamper shapes; **no**
      `rgb-lib`/`reqwest`/`tokio`/TLS crate in the graph; the **measured arm64** `.so` size; the
      16 KB alignment result (pass, or the blocker); Kotlin smoke green; Swift smoke green **in
      CI** (state the run)
- [ ] Write `minimal-sdk/rust-sdk/README.md`: quickstart (generate keys → register xpubs →
      prepare → verify → sign → complete) with Kotlin **and** Swift snippets; the
      verify-before-sign contract and what each of the five checks does; the **stated
      limitation** that RGB allocations on spent inputs are not verifiable client-side
      (`verify.ts:11-13`); the `HttpTransport` extension point; measured sizes for both
      platforms with the raw-vs-compressed and app-size-delta notes
- [ ] **State the Block-3 mobile runtime constraints and this SDK's answer to each**: it is a
      stateless client, so process death costs nothing beyond an in-flight request; every
      binding call is **blocking** and must not run on the Android main thread or the iOS main
      queue (say it plainly — the design doc flags ANR risk for the node SDK and it applies to
      any uniffi surface); there is no node, so the fail-fast watchdog and battery/chain-backend
      concerns do not apply. Being explicit about what does *not* apply is what makes the
      minimal variant's case
- [ ] Update `docs/design/mobile-sdk-and-lightweight-uniffi.md`: record that Paths A2 and A3
      were **superseded by a single Rust core**, add the measured 1.94 MB host figure and the
      measured arm64 figure, state the JNA cost honestly (≈2.46 MB vs ≈1.9 MB pure Kotlin) and
      why implementation count won over ~500 KB, and record the 16 KB alignment finding in
      Block 3 — the first time anything in this repo asserts it
- [ ] Update `minimal-sdk/README.md`: add the Rust core and both mobile packages to the
      architecture section; note `pnpm-workspace.yaml` is unaffected; state that the TypeScript
      SDK remains hand-written and is the **independent cross-check** on the Rust
      implementation, not legacy to be replaced
- [ ] Confirm `git status` shows only files this plan names, and that no Rust file under
      `src/`, no file under `bindings/`, no `packages/` file and no fixture was modified

## Post-Completion (manual, not for the agent)

- **Sign off the Apple path on real hardware.** Task 9 was written but never built locally, and
  Task 10's macOS job only proves it assembles. Run the Swift smoke on a device and an iOS
  simulator before any release.
- Build a throwaway consumer app on each platform with shrinking enabled and measure the
  **app-size delta** — the number users feel, and the only meaningful iOS number. The task
  gates measure artifacts, not deltas.
- Run one real end-to-end journey against a staging gateway from an Android device and an
  iPhone: register xpubs, prepare a send, verify, sign, complete. The suites here are entirely
  offline by design and prove parity, not integration.
- If the 16 KB alignment check failed, schedule the fix before any release targeting Android 15+.
- Decide publishing: Maven Central coordinates for the Android artifact and whether the Swift
  package ships as a tagged repo or a binary release. Nothing is published yet, so names are
  still free; coordinate with the node SDK's `rgb-lightning-node-android` line so the two are
  not confused.
- Decide whether the React Native SDK (`rgb-sdk-rn`) should adopt this Rust core via a native
  addon or stay on the TypeScript client SDK. Staying on TS preserves the independent
  cross-check this plan deliberately keeps; adopting the core would remove it.
- Re-measure the uniffi **node** numbers on real arm64 before quoting them externally (design
  doc Appendix C): every figure there is an x86_64 host build.
