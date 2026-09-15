# UTEXO minimal SDK — Android package

Kotlin bindings and JNI libraries for the minimal SDK core in
[`../rust-sdk`](../rust-sdk): keys, taproot derivation, verify-before-sign,
signing, invoice decoding and the gateway client, in one Rust implementation.
This is **not** the node: no LDK, no rgb-lib, no HTTP or TLS stack.

- Namespace `com.utexo.minimalsdk`, `minSdk 24`, `compileSdk 34`, AGP 8.7.3,
  Kotlin 1.9.24, JDK 17, own Gradle 8.9 wrapper.
- Runtime dependency: `net.java.dev.jna:jna:5.14.0@aar` only (uniffi's Kotlin
  bindings call Rust through JNA).
- Networking is the app's: implement `HttpTransport` (one synchronous `send`)
  over OkHttp or `HttpURLConnection` and hand it to `GatewayClient`. Rust
  performs no IO.

## Build

```sh
export JAVA_HOME=~/.jdks/temurin-17            # any JDK 17
../scripts/generate_bindings.sh kotlin          # uniffi library mode → generated/kotlin
../scripts/build_android.sh                     # cargo ndk (3 ABIs) → generated/jniLibs, then gates
./gradlew test                                  # JVM smoke test through the bindings
./gradlew assembleRelease                       # AAR in build/outputs/aar
```

`./gradlew test` and `assembleRelease` run the two scripts themselves when
their outputs are missing or stale. Requirements: Rust with the three Android
targets, `cargo-ndk`, an Android NDK (r28 or newer; `build_android.sh` picks
the newest under `$ANDROID_HOME/ndk`), and the Android SDK. The unit tests
load the **host** release cdylib through JNA, so `./gradlew test` needs cargo
but no NDK and no device.

Script options:

- `build_android.sh [--check-only] [jni_libs_dir]` — `--check-only` re-runs
  the gates on an existing tree without building; `jni_libs_dir` defaults to
  `generated/jniLibs`. Environment: `ANDROID_NDK_ROOT` / `ANDROID_NDK_HOME`
  (pin an NDK instead of the newest installed), `ANDROID_API` (minSdk the
  `.so` targets, default 24), `ANDROID_ARM64_BUDGET` (size gate in bytes,
  default 3000000).
- `generate_bindings.sh kotlin [output_dir] [library_path]` — `output_dir`
  defaults to `generated/kotlin`; pass `library_path` to generate from an
  existing unstripped build instead of running `cargo build --lib`.

## Release gates (`build_android.sh`, also `./gradlew checkAndroidJniLibs`)

1. **16 KB page alignment.** Every `PT_LOAD` segment of every produced `.so`
   must be aligned to at least 16384 bytes. Android 15+ requires it for native
   code; a misaligned library is a release blocker. NDK r28+ aligns the 64-bit
   ABIs by default but **not** `armeabi-v7a` (measured 4096 on r29), so the
   script passes `-Wl,-z,max-page-size=16384` to every target explicitly.
2. **Exported entry points.** Every `.so` must export the uniffi entry points
   (`llvm-nm -D` finds `uniffi_utexo_minimal_sdk_fn_func_sdk_version`); a
   library that lost them links fine and fails at the first JNA call.
3. **Size.** The single `arm64-v8a` slice must stay under **3.0 MB raw**.

Measured on 2026-09-15 with NDK r29 (29.0.14206865), release profile
`opt-level="z"`, thin LTO, stripped:

| Artifact                                    | Raw bytes |
| ------------------------------------------- | --------: |
| `arm64-v8a/libutexo_minimal_sdk.so`         | 2 366 720 |
| `armeabi-v7a/libutexo_minimal_sdk.so`       | 1 992 820 |
| `x86_64/libutexo_minimal_sdk.so`            | 2 508 984 |
| AAR (all three ABIs + 514 KB `classes.jar`) | 5 449 477 |
| JNA 5.14.0 AAR (consumer-side dependency)   |   517 894 |

What a device installs is one slice plus JNA: **≈2.88 MB on arm64**, matching
the plan's honest comparison of ≈2.46 MB (x86_64 host estimate) against
≈1.9 MB for pure Kotlin. Run `build_android.sh --check-only` to reprint the
current numbers; `../rust-sdk/tests/parity.rs` gates the host build at 2.5 MB.

**Install size tracks the raw `.so` number, not a compressed one.** APKs and
App Bundles store native libraries uncompressed (`extractNativeLibs=false`,
the default since API 23) so they can be mapped directly. About 1.06 MB of
each slice is libsecp256k1's precomputed tables, which any secp256k1 binding
(Rust or Kotlin) carries.

## One `.so` per device

The AAR carries all three ABIs. A consumer downloads one slice by shipping as
an **App Bundle** (Play serves the device's ABI) or by enabling ABI `splits`
on the app module; this library declares the same three-ABI split set so no
stray ABI is ever packaged.

## R8

`consumer-rules.pro` keeps only the JNA entry points the generated bindings
reach reflectively (the `Library` interface, `Structure` and `ByReference`
subclasses, `Callback` implementations) plus `RuntimeVisibleAnnotations`, which
JNA needs to read `@Structure.FieldOrder`. There is no blanket keep of
`com.utexo.minimalsdk`; the rest of the package shrinks like any Kotlin code.
