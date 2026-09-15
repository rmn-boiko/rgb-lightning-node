# UTEXO minimal SDK — Apple package

Swift bindings and an XCFramework for the minimal SDK core in
[`../rust-sdk`](../rust-sdk): keys, taproot derivation, verify-before-sign,
signing, invoice decoding and the gateway client, in one Rust implementation
shared with the [Android package](../android). This is **not** the node: no
LDK, no rgb-lib, no HTTP or TLS stack.

- Swift package `MinimalSdk` (module `MinimalSdk`, C module `MinimalSdkFFI`),
  swift-tools 5.9, Swift language mode 5.
- Deployment targets **iOS 15.0** and **macOS 12.0**, declared in
  `Package.swift` and pinned into every static library by `build_apple.sh`.
- No third-party dependencies. uniffi's Swift bindings call the Rust static
  library directly; there is no JNA equivalent to ship.
- Networking is the app's: `URLSessionHttpTransport` (one synchronous `send`,
  ephemeral session) is provided and any `HttpTransport` conformance can
  replace it. Rust performs no IO.

## Deployment-target policy

Both mobile packages use the same rule: the floor is the oldest OS version
that still covers about 98 % of the active installed base, so the SDK never
excludes a device its host app can reach. On Android that is API 24; on
Apple platforms that is iOS 15 (2021, the last iOS line Apple was still
patching in 2025) and its contemporary macOS 12 for the macOS slice. Raising
the floor is a one-line change in `Package.swift` plus the matching
`IOS_DEPLOYMENT_TARGET` / `MACOS_DEPLOYMENT_TARGET` in `build_apple.sh`; they
must move together.

## Build (macOS + Xcode)

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
                  aarch64-apple-darwin x86_64-apple-darwin
../scripts/build_apple.sh          # cargo (5 targets) → bindings → lipo → MinimalSdkFFI.xcframework
swift test                         # smoke test, runs on the macOS slice
```

`build_apple.sh` takes no arguments; its only knobs are the deployment-target
environment variables above. It builds release **static** libraries for the iOS device
target, the two iOS simulator targets and the two macOS targets, runs
`../scripts/generate_bindings.sh swift` (uniffi library mode, no UDL), lipos
the simulator and macOS slices into universal archives and calls
`xcodebuild -create-xcframework` with the device, simulator and macOS
libraries, each with the same headers directory
(`Sources/MinimalSdkFFI/{MinimalSdkFFI.h,module.modulemap}`). The macOS
slice exists so `swift test` runs natively on a Mac; an iOS app links only
the device slice.

Generated files (`Sources/MinimalSdk/Generated/`, `Sources/MinimalSdkFFI/`,
`MinimalSdkFFI.xcframework/`, `build/`) are not committed.

## Test on Linux (no Xcode)

The package has a Linux branch that mirrors what `test/swift-e2e` does for
the node: it links the host cdylib from `cargo build --release` through a
`systemLibrary` target instead of the XCFramework. It is a test aid only, not
a shipping configuration.

```sh
cargo build --release --lib --manifest-path ../rust-sdk/Cargo.toml
../scripts/generate_bindings.sh swift
swift test                                     # any Swift 5.9+ toolchain for Linux
```

Set `UTEXO_MINIMAL_SDK_LIB_DIR` to point at a different directory holding
`libutexo_minimal_sdk.so`.

## Size: measure the app-size delta, not the archive

iOS links statically and the app linker **dead-strips** the archive, so the
size of `libutexo_minimal_sdk.a` is not what the user downloads. The node's
XCFramework carries a 391.9 MB `.a` and that figure has misled before
(`docs/design/mobile-sdk-and-lightweight-uniffi.md`). The number that matters
for this package is the **delta in the app's installed size** with and
without the SDK linked, measured on a device build with App Thinning; expect
the same order as the Android arm64 slice (2.37 MB raw, of which about
1.06 MB is libsecp256k1's precomputed tables) as an upper bound, less after
dead-stripping of anything the app does not call. `build_apple.sh` prints
the archive sizes for the record and deliberately has no size gate; the Rust
size gate (`../rust-sdk/tests/parity.rs`, 2.5 MB host cdylib) and the Android
arm64 gate (`../scripts/build_android.sh`, 3.0 MB) bound the code that
reaches the app.

## What is verified where

The macOS column lists what the `apple` job of
`.github/workflows/minimal-sdk-mobile.yaml` runs; its current result is the
latest workflow run, not this table.

| Check                                                                                                                                             | Linux (this repo's dev machine) | macOS CI job                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- | ------------------------------ |
| Swift bindings generate in library mode, no UDL                                                                                                   | yes                             | yes                            |
| `bash -n` and `shellcheck` on both scripts                                                                                                        | yes                             | –                              |
| `Package.swift` parses (both `os()` branches)                                                                                                     | yes                             | yes                            |
| Swift smoke test (17 cases)                                                                                                                       | yes, against the host cdylib    | yes, against the macOS slice   |
| `URLSessionHttpTransport` through an in-process `URLProtocol` stub (status pass-through, verbatim headers and body, non-UTF-8 body, bounded wait) | yes                             | yes                            |
| iOS device + simulator static libraries                                                                                                           | **no** (needs Apple SDKs)       | yes                            |
| `lipo` and `xcodebuild -create-xcframework`                                                                                                       | **no** (needs Xcode)            | yes                            |
| uniffi entry points exported by the device slice                                                                                                  | **no**                          | yes (`nm` in `build_apple.sh`) |
