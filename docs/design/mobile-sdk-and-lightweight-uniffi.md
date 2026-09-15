# Mobile SDK: minimal client + lightweight uniffi node

Companion to `docs/design/minimal-sdk-and-lightweight-rln.md`, which covered the web
(wasm) side. That doc's Block 1 names "browser/mobile app" as the SDK target but only ever
analysed the TypeScript and wasm artifacts; the uniffi mobile SDK was never measured. This
one does that, and applies the same two-variant split to mobile.

All figures below were measured in this tree on 2026-09-14 (branch `dev`). Method and raw
output are in Appendix B. Numbers labelled *estimate* are derived, not measured.

## Executive summary

- **The mobile SDK ships the entire RLN daemon, not an SDK.** The uniffi cdylib is built
  from the root crate with `mod routes;` unconditional (`src/lib.rs:48`), so the axum REST
  server, both chain backends, both indexers, two ORMs and a **PostgreSQL driver** compile
  into the library that runs on a phone — while `src/uniffi_api/README.md:3` states "REST
  is **not** part of the SDK surface."
- **What CI uploads today is 99.0 MB, unstripped.** `uniffi-artifacts.yaml:59` copies
  `target/release/librgb_lightning_node.so` straight into the artifact. Stripping alone
  takes it to 73.4 MB.
- **The root `Cargo.toml` has no `[profile.release]`** — only `[profile.reldebug]`
  (`Cargo.toml:181`). This is the same gap the wasm crate had. Adding the three-line
  profile the wasm work already validated takes the library from **73.4 MB → 54.2 MB raw,
  28.3 MB → 20.1 MB gzip** (measured, not estimated).
- **Feature gating is worth about as much again**: dropping VLS, VSS, the second indexer
  and the PostgreSQL driver reaches **46.6 MB / 17.2 MB gzip** — a 53% cut from today,
  with no architectural change. The biggest code-level win still unmeasured is gating
  `mod routes` and converging the duplicated sea-orm/sqlx stacks.
- **For most mobile apps, none of that matters**, because the Minimal SDK variant applies
  unchanged: the existing TypeScript client SDK is **185.5 KB** and runs on React Native
  today with one polyfill. A native Kotlin equivalent costs about **1.9 MB** per ABI. That
  is ~28× smaller than the best tuned uniffi node and ~52× smaller than what CI ships.
- **One deadline has already passed.** Google Play requires 16 KB page-size support for
  native code targeting Android 15+; the extended deadline was 2026-05-31. The published
  SDK's AGP (8.7.3) aligns automatically, but this has never been verified on the produced
  `.so`, and the `android-e2e` harness is on AGP 8.3.0 — below the threshold.

## Block 1 — Minimal mobile SDK (the default recommendation)

The trust model, architecture and invariants I1–I4 are unchanged from the web design doc:
keys are generated and held client-side only, the server keeps per-user xpubs watch-only,
the gateway holds the only RLN credential, and the client verifies every server-prepared
PSBT before signing. Nothing about that is web-specific — only the implementation language
changes.

### Path A1 — reuse the TypeScript SDK (React Native / Capacitor). Days of work.

`minimal-sdk/packages/client-sdk` is already portable. Verified by inspection: it imports
only `@noble/*` and `@scure/*` (pure JS), and the sole platform touchpoints are
`globalThis.crypto.getRandomValues` (`src/gateway.ts:269`) and `globalThis.fetch`
(`src/gateway.ts:298`). There is no Node-only API anywhere in `src/`.

| Artifact | Size | Note |
| --- | --- | --- |
| `@utexo/minimal-client-sdk`, esbuild minified | **185.5 KB** | measured; budget gate is 500 KB |
| `react-native-get-random-values` polyfill | ~10 KB | estimate; RN lacks WebCrypto |

Capacitor needs no polyfill (it runs in a WebView with real WebCrypto). This is the
cheapest mobile path by a wide margin and the one to take unless the app is natively
written.

### Path A2 — native Kotlin. Weeks of work.

Reimplement the same five modules (`keys`, `derive`, `verify`, `sign`, `invoice`) over the
Kotlin equivalents of the `@scure` stack. Measured floor:

| Dependency | Size | Note |
| --- | --- | --- |
| `fr.acinq.bitcoin:bitcoin-kmp-jvm` | 596 KB jar (1.27 MB / 327 classes unpacked) | BIP-32/39, taproot, PSBT |
| `secp256k1-kmp-jni-android`, arm64-v8a slice | **1.28 MB** stripped | `.text` is only 195 KB; 1.12 MB is the precomputed ecmult table |
| **Total, arm64 slice** | **≈ 1.9 MB** | vs 54.2 MB for the tuned uniffi node |

Two things worth knowing. The secp256k1 library is 84% lookup table, so rebuilding it with
a smaller `--with-ecmult-window` trades signing speed for roughly 1 MB — usually not worth
it. And this path needs **no JNA**: `secp256k1-kmp` uses direct JNI, so the 518 KB
`net.java.dev.jna:jna:5.14.0@aar` that the uniffi SDK pulls in
(`bindings/kotlin-android-sdk/build.gradle.kts`) disappears entirely. That aar also still
ships dead `mips`/`mips64` slices (293 KB of its 518 KB) that Android dropped in NDK r17.

### Path A3 — native Swift. Weeks of work.

`swift-secp256k1` over the same libsecp256k1 C core; the size profile is dominated by the
same ecmult table, so expect the same order as A2 (*estimate*: 0.3–1.3 MB depending on the
ecmult window). iOS links statically and dead-strips at app link, so measure the app-size
delta rather than the library.

### What this buys

The custody boundary is identical to the web variant and must be stated the same way: the
client keys cover all at-rest user funds, the LN working balance on the shared node stays
custodial, and the mitigations are the capped float, the sweep threshold and the swap path.
Mobile changes none of that.

## Block 2 — Lightweight uniffi node (when the app must run its own node)

### Where the size goes (measured)

`cargo build --release --features "uniffi,vls,vss"` (defaults on), host
`x86_64-unknown-linux-gnu`:

| Build | `.so` raw | gzip | `.text` |
| --- | --- | --- | --- |
| What CI uploads today — **unstripped** (`uniffi-artifacts.yaml:59`) | 99.0 MB | — | 57.2 MB |
| Same, `strip --strip-all` | 73.4 MB | 28.3 MB | 57.2 MB |
| **+ `opt-level="z"` + thin LTO + `strip`** | **54.2 MB** | **20.1 MB** | 32.7 MB |
| + drop VLS, VSS, second indexer | 47.9 MB | 17.7 MB | 27.5 MB |
| **+ drop the PostgreSQL driver too** | **46.6 MB** | **17.2 MB** | 26.8 MB |
| + `panic="abort"` instead (measured, **not recommended** — see below) | 44.5 MB | 16.5 MB | 26.4 MB |

So the realistic, recommendable floor with no architectural change is **46.6 MB raw /
17.2 MB gzip** — a 53% cut from what CI ships today, reached entirely through a build
profile, four feature flags and one dependency line.

The iOS side ships a 391.9 MB static `.a` inside the XCFramework
(`scripts/ci/package_swift_xcframework.sh`), but that is an archive: the app linker
dead-strips it, so the meaningful iOS number is the app-size delta, which nobody in this
repo has measured yet.

Attribution of the baseline `.text` (56.7 MB attributed across 93,494 symbols):

| Subsystem | Share |
| --- | --- |
| Rust `core` + `alloc` + `std` | 27.1% |
| LDK (fork + companion crates) | 15.4% |
| RGB stack (rgb-lib, rgbcore/std, strict_encoding, amplify…) | 12.5% |
| Database stack — sea-orm ×2, sqlx ×2 **including PostgreSQL** | 5.7% |
| VLS validating signer + redb ×2 | 2.8% |
| Own code (`rgb_lightning_node`) | 2.9% |
| REST server (axum, tower, hyper, h2, biscuit-auth) | 1.7% |
| TLS/crypto stacks (rustls, aws-lc, ring) | 1.7% |
| Both indexers (electrum + esplora) | 0.8% |
| C code in the remainder: aws-lc 1.38 MB, sqlite3 0.66 MB, zstd/zlib 0.61 MB, **secp256k1 0.15 MB** | — |

Two structural differences from the wasm build are worth internalising:

- **Exports are not the problem here.** The cdylib exposes 234 dynamic symbols (156
  uniffi). The wasm build's 569 `wasm-bindgen` exports pinned its whole call graph; this
  one is pinned by genuine reachability from 156 entry points instead. Trimming exports
  will not help much — gating modules will.
- **Unwinding metadata is 23% of the tuned binary**: `.eh_frame` 7.56 MB +
  `.eh_frame_hdr` 1.16 MB + `.gcc_except_table` 3.87 MB = 12.6 MB of 54.2 MB. This is the
  price of `panic = "unwind"`, and it has no wasm equivalent.

### The dead weight, specifically

| Finding | Evidence |
| --- | --- |
| The REST server compiles into the phone library, contradicting the SDK's own README | `src/lib.rs:48` (`mod routes;` unconditional) vs `src/uniffi_api/README.md:3` |
| A PostgreSQL driver ships to mobile | `migration/Cargo.toml:15` (`sqlx-postgres`) |
| The ORM is compiled twice — rgb-lib pins sea-orm 2.0.2, RLN pins 1.1.20, so `sqlx-core`/`-postgres`/`-sqlite` each build at 0.8.6 **and** 0.9.0 | `Cargo.toml:44`, `migration/Cargo.toml:12`, `Cargo.lock` |
| Both chain backends are forced on, because the UDL enum has both variants — a phone never runs bitcoind | `src/lib.rs:16-19`, `bindings/rgb_lightning_node.udl:605-608` |
| Three crypto stacks resolve; vendored OpenSSL is **built** (this is why CI needs bindgen + cmake) but the linker strips it from the cdylib — pure build-time waste | `Cargo.toml:97`, `uniffi-artifacts.yaml:118-124`, symbol scan |
| aws-lc contributes 1.38 MB, of which 680 KB is x86 AES-GCM AVX-512 assembly — a TLS suite for a wallet that needs secp256k1 (0.15 MB) | symbol scan |
| 769 crates in the dependency graph | `Cargo.lock` |

### Build checklist

**Phase 0 — config only, one small PR. Measured: 73.4 MB → 54.2 MB raw, 28.3 → 20.1 MB gzip.**

1. **Add `[profile.release]`** to the root `Cargo.toml`: `opt-level = "z"`, `lto = "thin"`,
   `strip = "symbols"`. Three lines. This is the same change the wasm work already
   validated. Verify the latency impact on signing paths before adopting `opt-level="z"`
   over `"s"` — `z` disables loop vectorisation, and the RGB/LDK hot paths were never
   profiled on ARM.
2. **Strip in CI regardless.** `uniffi-artifacts.yaml:59` ships an unstripped `.so`; that
   alone is 25.6 MB of the current artifact.
3. **`--remap-path-prefix`** via `RUSTFLAGS` in the mobile workflows — same privacy leak
   and reproducibility prerequisite as wasm checklist item 4.

**Phase 1 — scoped feature gating. Measured 47.9 MB for the features alone; the code-level items are unmeasured.**

4. **`#[cfg(feature = "rest")] mod routes;`** and move `axum`, `axum-extra`, `tower-http`
   and `biscuit-auth` behind it. The layering already supports this — `src/uniffi_api/README.md`
   documents `uniffi_api -> sdk -> ldk` with `routes` as a parallel compatibility layer that
   uniffi never calls.
5. **Drop `sqlx-postgres`** from `migration/Cargo.toml` for mobile builds, and converge the
   sea-orm major version with rgb-lib's to collapse the duplicate ORM and sqlx trees.
6. **Un-force the chain backend**: keep both `SdkLdkChainSync` variants in the UDL (stable
   ABI) but return a runtime error for a backend that was not compiled, then drop the
   `compile_error!` at `src/lib.rs:16-19`. Mobile builds `transaction-sync` only.
7. **One indexer per build**, and gate VLS/VSS off for integrators who do not use them.

**Phase 2 — deeper, do last.**

8. **`-Zbuild-std` + `panic_immediate_abort`** (nightly, CI-only lane) attacks the 27%
   `core`/`alloc` share — the single largest slice, exactly as on the wasm side.
9. **`panic = "abort"` is measured at −9.7 MB (18%) but should not be adopted.** uniffi
   converts Rust panics into Kotlin/Swift exceptions by catching them at the FFI boundary,
   and the background-processor watchdog depends on `catch_unwind` (`src/ldk.rs:4379-4422`).
   With `panic="abort"` a recoverable error becomes a hard app crash. The number is
   recorded here so the trade is explicit, not so it gets taken.

### Mobile packaging (this is where mobile differs from web)

- **Google Play caps the per-device compressed download at 200 MB** for an app bundle, and
  warns users on mobile data above that. With ABI splits each user downloads one `.so`, so
  even today's build fits — size here is a product-quality problem, not a compliance one.
- **Install size is what users actually feel.** With the modern default
  (`useLegacyPackaging = false`) the `.so` is stored uncompressed and page-mapped from the
  APK, so the install footprint tracks the *raw* size — 54.2 MB tuned versus 73.4 MB
  stripped versus 99.0 MB as shipped. This is the number to put in the checklist, not the
  gzip column.
- **16 KB page size is now mandatory** for native code targeting Android 15+ (extended
  deadline 2026-05-31, already passed). AGP ≥ 8.5.1 aligns at packaging and the published
  SDK uses 8.7.3, so this is probably fine — but it has never been asserted on the produced
  `.so`, and `android-e2e/build.gradle` is on AGP 8.3.0. Add a CI check that reads the
  `LOAD` segment alignment of each `jniLibs` artifact.
- **iOS thins automatically**: the App Store ships only the device's slice, and the static
  `.a` is dead-stripped at app link. The XCFramework currently carries device arm64 plus a
  universal simulator slice (`scripts/ci/package_swift_xcframework.sh`), which is correct.
- **Nothing is published yet.** Maven Central has no `com.utexo` artifacts, so all of the
  above can land before the first release rather than as a breaking change after it.

## Block 3 — Mobile runtime constraints

These have no web analogue and are not addressed anywhere in the current SDK:

- **Process death is normal, not exceptional.** Android kills backgrounded processes freely
  and iOS suspends them within seconds. A Lightning node that assumes a long-lived process
  will miss channel updates. The uniffi surface is instance-based (`SdkNode.create`, per
  `src/uniffi_api/README.md`) but there is no documented save/restore-on-suspend contract.
- **The threading model bridges sync FFI onto async internals** via `block_in_place +
  handle.block_on` on a multi-thread runtime, or a dedicated runtime otherwise
  (`src/uniffi_api/README.md`). Every uniffi call therefore blocks the calling thread —
  calling one from the Android main thread will ANR. This needs to be stated in the SDK
  README, and ideally enforced with a debug-build assertion.
- **The fail-fast watchdog is wrong for an app.** `src/ldk.rs:4422` calls
  `std::process::exit` on an event-path panic. On a daemon that is correct; inside a host
  app it terminates the user's whole application, bypassing every crash reporter. Mobile
  builds should surface a fatal error through the FFI instead. This overlaps with item 5 of
  the web doc's Block 3 fix list and should be designed alongside it.
- **Battery and data.** Both chain backends and both indexers being compiled in is a size
  problem; which one is *used* is a battery problem. Mobile should default to
  `transaction-sync` against an indexer with an explicit polling cadence, never a full
  block sync.

## Appendix

### A. Citation index

- Crate layout / profile gap: `Cargo.toml:7-9` (`crate-type`), `Cargo.toml:181`
  (`reldebug`, no `[profile.release]`), `Cargo.toml:27-60` (features), `Cargo.toml:97`
  (reqwest `native-tls`)
- Daemon in the SDK: `src/lib.rs:48` (`mod routes;`), `src/lib.rs:16-19` (`compile_error!`
  forcing both chain backends), `src/uniffi_api/README.md:3` (REST is not the SDK surface)
- Bindings: `bindings/rgb_lightning_node.udl:605-608` (`SdkLdkChainSync`), 918 lines / 99
  interfaces+dictionaries+enums; `src/uniffi_api/mod.rs` (~110 public functions);
  `uniffi.toml`, `uniffi-android.toml`
- CI: `.github/workflows/uniffi-artifacts.yaml:50,59` (release build, unstripped copy),
  `:126-135` (Android JNI via `scripts/ci/build_android_jni.sh`), `:202-205` (Apple
  targets), `scripts/ci/package_swift_xcframework.sh`
- Android packaging: `bindings/kotlin-android-sdk/build.gradle.kts` (AGP 8.7.3, JNA aar,
  `isMinifyEnabled = false`), `android-e2e/build.gradle` (AGP 8.3.0)
- Database: `migration/Cargo.toml:12-18` (`cli`, `sqlx-postgres`, `sqlx-sqlite`)
- Watchdog / panic path: `src/ldk.rs:4379` (`catch_unwind`), `src/ldk.rs:4422`
  (`process::exit`)
- Client SDK portability: `minimal-sdk/packages/client-sdk/src/gateway.ts:269,298`

### B. Measured numbers and method

Host `x86_64-unknown-linux-gnu`, Rust stable, this tree at `dev`, 2026-09-14. Profile
variants applied via `CARGO_PROFILE_RELEASE_*` environment overrides so no file was
modified. Sizes from `stat`/`size -A`; gzip is `gzip -9`. Symbol attribution from
`nm --print-size --size-sort -C` on the unstripped baseline, aggregating `t`/`w` symbols by
the leading path component of the demangled name; 6.08 MB of unmangled (C) symbols were
classified separately by name prefix.

| # | Build | `.so` | gzip | `.text` |
| --- | --- | --- | --- | --- |
| 1 | `--release --features "uniffi,vls,vss"`, as CI ships it | 99.0 MB | — | 57.2 MB |
| 2 | #1 stripped | 73.4 MB | 28.3 MB | 57.2 MB |
| 3 | #1 + `opt-level=z`, `lto=thin`, `strip=symbols` | 54.2 MB | 20.1 MB | 32.7 MB |
| 4 | #3 + `--no-default-features --features "uniffi,electrum,block-sync,transaction-sync"` | 47.9 MB | 17.7 MB | 27.5 MB |
| 5 | #4 + `sqlx-postgres` removed from `migration/Cargo.toml` (edit reverted after the build) | 46.6 MB | 17.2 MB | 26.8 MB |
| 6 | #3 + `panic=abort` | 44.5 MB | 16.5 MB | 26.4 MB |

Static library for iOS: 391.9 MB `.a`, 104.9 MB `.rlib`. Dynamic exports: 234 total, 156
uniffi. Dependency graph: 769 crates.

Section breakdown of build #3 (54.2 MB): `.text` 32.65, `.eh_frame` 7.56, `.rodata` 5.42,
`.rela.dyn` 3.86, `.gcc_except_table` 3.87, `.eh_frame_hdr` 1.16, `.data.rel.ro` 1.58 (MB).

Third-party artifacts, downloaded from Maven Central and measured: `jna-5.14.0.aar`
517,894 B (arm64 slice 168,176 B; dead mips/mips64 slices 292,828 B);
`secp256k1-kmp-jni-android-0.15.0.aar` 4,902,570 B (arm64 `.so` 1,339,880 B, already
stripped: `.text` 194,820 B, `.rodata` 1,119,480 B); `bitcoin-kmp-jvm-0.20.0.jar`
596,300 B. TypeScript client SDK: 185.5 KB via the repo's own esbuild bundle gate.

### C. What was not measured

- **Android arm64 and iOS arm64 code size.** No NDK or macOS host was available here, so
  every figure is the x86_64 host build. Rust `.text` on aarch64 is typically within ±15%
  of x86_64, but the aws-lc assembly differs substantially (the 680 KB of AVX-512 AES-GCM
  is replaced by smaller ARM crypto-extension code). **Re-measure on the real targets
  before quoting these numbers externally.**
- **The app-size delta on iOS**, which is the only number that matters there.
- **Phase-1 code-level gating** (items 4–6): only the feature-flag portion was measured.
- **Runtime cost of `opt-level="z"`** on signing and sync paths.
