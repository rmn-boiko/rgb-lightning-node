#!/usr/bin/env bash
# Build the minimal SDK core for Apple platforms and package it as an
# XCFramework for the Swift package in minimal-sdk/apple.
#
# Usage: build_apple.sh
#
# Modelled on scripts/ci/package_swift_xcframework.sh. Steps:
#   1. cargo build --release --lib (staticlib) for the iOS device target,
#      the two iOS simulator targets and the two macOS targets
#   2. generate_bindings.sh swift (library mode, from the unstripped host
#      build); the header + modulemap land in
#      minimal-sdk/apple/Sources/MinimalSdkFFI which doubles as the
#      XCFramework headers directory
#   3. lipo the simulator slices into one universal .a, same for macOS
#   4. xcodebuild -create-xcframework with device + simulator + macOS
#      libraries, each with the headers directory
#   5. sanity: the device slice exports the uniffi symbols; print sizes
#
# The macOS slice exists so `swift test` can run the smoke test natively on
# a macOS host; the iOS app links the device slice only.
#
# Sizes printed here are archive sizes and are NOT the number that matters:
# iOS links statically and dead-strips at app link, so the meaningful figure
# is the app-size delta. There is deliberately no size gate in this script;
# the Rust size gate (tests/parity.rs) and the Android arm64 gate
# (build_android.sh) bound the code that ends up in the app.
#
# Requires macOS with Xcode (xcodebuild, lipo, nm) and the five Rust targets
# (rustup target add ...). Not runnable on Linux; the Swift package's Linux
# branch links the host cdylib directly instead.
#
# Environment:
#   IOS_DEPLOYMENT_TARGET    minimum iOS (default 15.0, must match Package.swift)
#   MACOS_DEPLOYMENT_TARGET  minimum macOS (default 12.0, must match Package.swift)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUST_SDK_DIR="$REPO_ROOT/minimal-sdk/rust-sdk"
APPLE_DIR="$REPO_ROOT/minimal-sdk/apple"
LIB_BASENAME="libutexo_minimal_sdk.a"
FFI_MODULE="MinimalSdkFFI"
HEADERS_DIR="$APPLE_DIR/Sources/$FFI_MODULE"
BUILD_DIR="$APPLE_DIR/build"
XCFRAMEWORK="$APPLE_DIR/$FFI_MODULE.xcframework"
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-15.0}"
MACOS_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET:-12.0}"

IOS_DEVICE_TARGET=aarch64-apple-ios
IOS_SIM_TARGETS=(aarch64-apple-ios-sim x86_64-apple-ios)
MACOS_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
ALL_TARGETS=("$IOS_DEVICE_TARGET" "${IOS_SIM_TARGETS[@]}" "${MACOS_TARGETS[@]}")

[[ $# -eq 0 ]] || {
  echo "usage: $0 (no arguments; see the header for environment variables)" >&2
  exit 1
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found"
}

[[ "$(uname -s)" == "Darwin" ]] ||
  die "XCFramework packaging needs macOS + Xcode; on Linux use 'swift test' in minimal-sdk/apple against the host cdylib"
need_cmd cargo
need_cmd rustup
need_cmd xcodebuild
need_cmd lipo
need_cmd nm

INSTALLED_TARGETS="$(rustup target list --installed)"
for t in "${ALL_TARGETS[@]}"; do
  grep -qx "$t" <<<"$INSTALLED_TARGETS" || die "Rust target $t not installed: rustup target add $t"
done

TARGET_DIR="${CARGO_TARGET_DIR:-$RUST_SDK_DIR/target}"

# ---- 1. Static libraries -------------------------------------------------
# The deployment targets are pinned so every object in the archive records
# the same minimum OS as Package.swift declares; an archive built for a
# newer minimum than the app fails at link with an unhelpful ld warning.
export IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"
export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"
echo "Building release static libraries (iOS >= $IOS_DEPLOYMENT_TARGET, macOS >= $MACOS_DEPLOYMENT_TARGET)"
for t in "${ALL_TARGETS[@]}"; do
  echo "  cargo build --release --lib --target $t"
  cargo build --release --lib --manifest-path "$RUST_SDK_DIR/Cargo.toml" --target "$t"
  [[ -f "$TARGET_DIR/$t/release/$LIB_BASENAME" ]] || die "missing $TARGET_DIR/$t/release/$LIB_BASENAME"
done

# ---- 2. Swift bindings, header and modulemap ---------------------------
"$SCRIPT_DIR/generate_bindings.sh" swift
[[ -f "$HEADERS_DIR/$FFI_MODULE.h" && -f "$HEADERS_DIR/module.modulemap" ]] ||
  die "generate_bindings.sh swift did not produce $HEADERS_DIR/{$FFI_MODULE.h,module.modulemap}"

# ---- 3. Universal simulator and macOS archives ---------------------------
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/ios-simulator" "$BUILD_DIR/macos"
SIM_INPUTS=()
for t in "${IOS_SIM_TARGETS[@]}"; do
  SIM_INPUTS+=("$TARGET_DIR/$t/release/$LIB_BASENAME")
done
lipo -create "${SIM_INPUTS[@]}" -output "$BUILD_DIR/ios-simulator/$LIB_BASENAME"
MAC_INPUTS=()
for t in "${MACOS_TARGETS[@]}"; do
  MAC_INPUTS+=("$TARGET_DIR/$t/release/$LIB_BASENAME")
done
lipo -create "${MAC_INPUTS[@]}" -output "$BUILD_DIR/macos/$LIB_BASENAME"

# ---- 4. XCFramework ------------------------------------------------------
DEVICE_LIB="$TARGET_DIR/$IOS_DEVICE_TARGET/release/$LIB_BASENAME"
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
  -library "$DEVICE_LIB" -headers "$HEADERS_DIR" \
  -library "$BUILD_DIR/ios-simulator/$LIB_BASENAME" -headers "$HEADERS_DIR" \
  -library "$BUILD_DIR/macos/$LIB_BASENAME" -headers "$HEADERS_DIR" \
  -output "$XCFRAMEWORK"

# ---- 5. Sanity and numbers ----------------------------------------------
# An archive that lost its exported uniffi entry points (wrong crate-type,
# LTO dropping them) links fine and fails at first call; catch it here.
nm -g "$DEVICE_LIB" 2>/dev/null | grep -q "_uniffi_utexo_minimal_sdk_fn_func_sdk_version" ||
  die "$DEVICE_LIB does not export the uniffi entry points"

echo "Apple static library sizes (archive bytes; NOT install size, see README):"
for t in "${ALL_TARGETS[@]}"; do
  printf '  %-24s %10d bytes\n' "$t" "$(stat -f %z "$TARGET_DIR/$t/release/$LIB_BASENAME")"
done
printf '  %-24s %10d bytes (lipo)\n' "ios-simulator universal" "$(stat -f %z "$BUILD_DIR/ios-simulator/$LIB_BASENAME")"
printf '  %-24s %10d bytes (lipo)\n' "macos universal" "$(stat -f %z "$BUILD_DIR/macos/$LIB_BASENAME")"
echo "Packaged $XCFRAMEWORK"
