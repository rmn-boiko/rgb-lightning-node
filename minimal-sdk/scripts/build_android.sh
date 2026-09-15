#!/usr/bin/env bash
# Cross-compile the minimal SDK core for Android and check the result.
#
# Usage: build_android.sh [--check-only] [jni_libs_dir]
#
# Modelled on scripts/ci/build_android_jni.sh (`cargo ndk` per ABI). The aws-lc
# cleanup that script performs is node-specific and deliberately NOT carried
# over: this crate has no aws-lc.
#
# After building (or with --check-only, on an existing jniLibs tree) this
# script enforces three release gates on every produced .so:
#
# 1. 16 KB page alignment: every PT_LOAD segment must be aligned to >= 16384.
#    Android 15+ requires it for native code (Play deadline 2026-05-31, passed).
#    A misaligned library is a release blocker; the fix is NDK r28+ (aligns by
#    default) or `-Wl,-z,max-page-size=16384` on older NDKs.
# 2. Exports: every .so must export the uniffi entry points (a wrong
#    crate-type or LTO dropping them links fine and fails at first call).
# 3. Size: the single arm64-v8a slice must stay under ANDROID_ARM64_BUDGET
#    bytes (3.0 MB). Install size tracks this RAW number, not a compressed one.
#
# Environment:
#   ANDROID_NDK_ROOT / ANDROID_NDK_HOME  NDK to use (default: newest under
#                                        $ANDROID_HOME/ndk or ~/Android/Sdk/ndk)
#   ANDROID_API                          minSdk the .so targets (default 24)
#   ANDROID_ARM64_BUDGET                 arm64-v8a raw-size budget in bytes
#                                        (default 3000000)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUST_SDK_DIR="$REPO_ROOT/minimal-sdk/rust-sdk"
ANDROID_DIR="$REPO_ROOT/minimal-sdk/android"
LIB_NAME="libutexo_minimal_sdk.so"
ABIS=(arm64-v8a armeabi-v7a x86_64)
ANDROID_API="${ANDROID_API:-24}"
# Raw bytes for the arm64-v8a slice. The Rust size gate (tests/parity.rs) is
# 2.5 MB on the x86_64 host build; arm64 code is denser but the budget leaves
# room for the NDK's unwind tables and alignment padding.
ANDROID_ARM64_BUDGET="${ANDROID_ARM64_BUDGET:-3000000}"
REQUIRED_PAGE_ALIGN=16384

CHECK_ONLY=0
if [[ "${1:-}" == "--check-only" ]]; then
  CHECK_ONLY=1
  shift
fi
OUT_DIR="${1:-$ANDROID_DIR/generated/jniLibs}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found"
}

resolve_ndk() {
  local candidate="${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:-}}"
  if [[ -z "$candidate" ]]; then
    local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
    if [[ -d "$sdk/ndk" ]]; then
      candidate="$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
    fi
  fi
  [[ -n "$candidate" && -f "$candidate/source.properties" ]] ||
    die "no Android NDK found; install one with 'sdkmanager \"ndk;<version>\"' or set ANDROID_NDK_ROOT"
  echo "$candidate"
}

NDK_ROOT="$(resolve_ndk)"
NDK_VERSION="$(sed -n 's/^Pkg.Revision = //p' "$NDK_ROOT/source.properties")"
NDK_BIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [[ ! -d "$NDK_BIN" ]]; then
  NDK_BIN="$(find "$NDK_ROOT/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d | head -n 1)/bin"
fi
READELF="$NDK_BIN/llvm-readelf"
[[ -x "$READELF" ]] || READELF="$(command -v llvm-readelf || command -v readelf || true)"
[[ -n "$READELF" ]] || die "no readelf available (expected $NDK_BIN/llvm-readelf)"
NM="$NDK_BIN/llvm-nm"
[[ -x "$NM" ]] || NM="$(command -v llvm-nm || command -v nm || true)"
[[ -n "$NM" ]] || die "no nm available (expected $NDK_BIN/llvm-nm)"

# Portable file size in bytes (GNU stat -c and BSD stat -f differ; wc does not).
file_size() {
  wc -c <"$1" | tr -d '[:space:]'
}

if [[ "$CHECK_ONLY" == "0" ]]; then
  need_cmd cargo
  cargo ndk --version >/dev/null 2>&1 || die "cargo-ndk not installed: cargo install cargo-ndk"
  export ANDROID_NDK_ROOT="$NDK_ROOT"
  export ANDROID_NDK_HOME="$NDK_ROOT"
  echo "Using NDK $NDK_VERSION at $NDK_ROOT (API $ANDROID_API)"
  rm -rf "$OUT_DIR"
  mkdir -p "$OUT_DIR"
  # NDK r28+ links the 64-bit ABIs with 16 KB max-page-size by default but
  # leaves 32-bit arm at 4 KB (measured on r29: armeabi-v7a PT_LOAD align
  # 0x1000). Android's 16 KB page mode only exists on 64-bit devices, so that
  # is not a runtime bug, but the gate below applies to EVERY shipped .so so
  # the AAR is uniformly aligned. Ask the linker explicitly for all targets;
  # for arm64/x86_64 this restates the default.
  PAGE_ALIGN_FLAG="-C link-arg=-Wl,-z,max-page-size=$REQUIRED_PAGE_ALIGN"
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="${CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS:-} $PAGE_ALIGN_FLAG"
  export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS="${CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS:-} $PAGE_ALIGN_FLAG"
  export CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS="${CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS:-} $PAGE_ALIGN_FLAG"
  # One invocation for all three ABIs; cargo-ndk lays the output out as
  # <out>/<abi>/$LIB_NAME, the jniLibs layout Gradle expects.
  (
    cd "$RUST_SDK_DIR"
    cargo ndk \
      --platform "$ANDROID_API" \
      -t arm64-v8a -t armeabi-v7a -t x86_64 \
      -o "$OUT_DIR" \
      build --release --lib
  )
fi

# ---- Gate 1: 16 KB page alignment on every PT_LOAD segment of every .so ----
check_alignment() {
  local so="$1"
  local ok=1
  local found=0
  local align
  # llvm-readelf -lW prints one "  LOAD  off vaddr paddr filesz memsz flags align" line per segment.
  while read -r align; do
    found=1
    align=$(( align )) # readelf prints hex (0x4000); bash arithmetic parses it
    if (( align < REQUIRED_PAGE_ALIGN )); then
      echo "  FAIL $so: PT_LOAD align $align < $REQUIRED_PAGE_ALIGN" >&2
      ok=0
    fi
  done < <("$READELF" -lW "$so" | awk '$1 == "LOAD" { print $NF }')
  (( found == 1 )) || die "$so has no PT_LOAD segments (not an ELF shared object?)"
  (( ok == 1 ))
}

echo "Checking 16 KB page alignment (PT_LOAD align >= $REQUIRED_PAGE_ALIGN):"
ALIGN_OK=1
for abi in "${ABIS[@]}"; do
  so="$OUT_DIR/$abi/$LIB_NAME"
  [[ -f "$so" ]] || die "missing $so"
  if check_alignment "$so"; then
    echo "  ok   $abi"
  else
    ALIGN_OK=0
  fi
done
(( ALIGN_OK == 1 )) ||
  die "16 KB alignment check failed (release blocker). Use NDK r28+ or add -Wl,-z,max-page-size=16384; NDK in use: $NDK_VERSION"

# ---- Gate 2: the uniffi entry points are exported from every .so -----------
# JNA resolves these by name at first call; the same check build_apple.sh
# runs on the iOS device slice.
ENTRY_POINT="uniffi_utexo_minimal_sdk_fn_func_sdk_version"
echo "Checking exported uniffi entry points ($ENTRY_POINT):"
for abi in "${ABIS[@]}"; do
  so="$OUT_DIR/$abi/$LIB_NAME"
  "$NM" -D --defined-only "$so" 2>/dev/null | awk '{ print $NF }' | grep -qx "$ENTRY_POINT" ||
    die "$so does not export $ENTRY_POINT (wrong crate-type or stripped exports?)"
  echo "  ok   $abi"
done

# ---- Gate 3: arm64 raw size budget, plus the numbers worth recording ----
echo "Android library sizes (raw bytes; install size tracks raw, not compressed):"
for abi in "${ABIS[@]}"; do
  so="$OUT_DIR/$abi/$LIB_NAME"
  printf '  %-12s %10d bytes\n' "$abi" "$(file_size "$so")"
done
for aar in "$ANDROID_DIR"/build/outputs/aar/*.aar; do
  [[ -f "$aar" ]] || continue
  printf '  %-12s %10d bytes (%s)\n' "aar" "$(file_size "$aar")" "$(basename "$aar")"
done
jna_aar="$(find "${GRADLE_USER_HOME:-$HOME/.gradle}/caches/modules-2/files-2.1/net.java.dev.jna/jna/5.14.0" -name 'jna-5.14.0.aar' 2>/dev/null | head -n 1 || true)"
if [[ -n "$jna_aar" ]]; then
  printf '  %-12s %10d bytes (net.java.dev.jna:jna:5.14.0@aar, consumer-side dependency)\n' "jna" "$(file_size "$jna_aar")"
fi

ARM64_BYTES="$(file_size "$OUT_DIR/arm64-v8a/$LIB_NAME")"
if (( ARM64_BYTES >= ANDROID_ARM64_BUDGET )); then
  die "arm64-v8a $LIB_NAME is $ARM64_BYTES bytes, over the $ANDROID_ARM64_BUDGET byte budget"
fi
echo "Android size gate: arm64-v8a $ARM64_BYTES bytes < $ANDROID_ARM64_BUDGET budget (NDK $NDK_VERSION)"
echo "Android JNI libs OK in $OUT_DIR"
