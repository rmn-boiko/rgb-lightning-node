#!/usr/bin/env bash
# Generate Kotlin or Swift bindings for the minimal SDK core in uniffi
# LIBRARY MODE: the crate is proc-macro only, there is no UDL file and none
# may be added (docs/plans/20260915-minimal-mobile-rust-sdk.md, Task 1).
#
# Usage: generate_bindings.sh <kotlin|swift> [output_dir] [library_path]
#
# Library mode reads the UNIFFI_META_* symbols from the built library's
# symbol table. The release profile strips symbols, so bindings are generated
# from an UNSTRIPPED host DEBUG build (`cargo build --lib`). The metadata is
# profile- and target-independent, so the output matches the stripped release
# and the cross-compiled Android/iOS libraries exactly.
#
# Output layout:
#   kotlin  <output_dir>/com/utexo/minimalsdk/utexo_minimal_sdk.kt
#           (default output_dir: minimal-sdk/android/generated/kotlin)
#   swift   <output_dir>/MinimalSdk.swift            the Swift sources
#           <ffi_dir>/MinimalSdkFFI.h                 the C header
#           <ffi_dir>/module.modulemap               the modulemap
#           (default output_dir: minimal-sdk/apple/Sources/MinimalSdk/Generated;
#            ffi_dir is always   minimal-sdk/apple/Sources/MinimalSdkFFI)
#
# library_path defaults to an unstripped host debug build made here; pass a
# path to reuse an existing build instead.
#
# The Swift header and modulemap are split out of the Swift source directory
# because they serve two masters that must see the same bytes: on Apple
# platforms build_apple.sh hands <ffi_dir> to `xcodebuild -create-xcframework`
# as the XCFramework's headers; on Linux Package.swift points a systemLibrary
# target at it so `swift test` can run the smoke test against the host cdylib.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUST_SDK_DIR="$REPO_ROOT/minimal-sdk/rust-sdk"
APPLE_DIR="$REPO_ROOT/minimal-sdk/apple"
BINDGEN_MANIFEST="$REPO_ROOT/bindings/uniffi-bindgen/Cargo.toml"
CONFIG_PATH="$RUST_SDK_DIR/uniffi.toml"
CRATE_NAME="utexo_minimal_sdk"
SWIFT_MODULE="MinimalSdk"
SWIFT_FFI_MODULE="MinimalSdkFFI"

LANGUAGE="${1:-}"
if [[ "$LANGUAGE" != "kotlin" && "$LANGUAGE" != "swift" ]]; then
  echo "usage: $0 <kotlin|swift> [output_dir] [library_path]" >&2
  exit 1
fi

OUT_DIR="${2:-}"
if [[ -z "$OUT_DIR" ]]; then
  case "$LANGUAGE" in
    kotlin) OUT_DIR="$REPO_ROOT/minimal-sdk/android/generated/kotlin" ;;
    swift) OUT_DIR="$APPLE_DIR/Sources/$SWIFT_MODULE/Generated" ;;
  esac
fi
SWIFT_FFI_DIR="$APPLE_DIR/Sources/$SWIFT_FFI_MODULE"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command '$1' not found" >&2
    exit 1
  }
}
need_cmd cargo

# Guard the library-mode contract: a UDL file would silently take precedence
# in the node's scripts and would drift from the proc-macro surface here.
if compgen -G "$RUST_SDK_DIR/src/*.udl" >/dev/null; then
  echo "ERROR: $RUST_SDK_DIR/src contains a .udl file; the minimal SDK is proc-macro only" >&2
  exit 1
fi

LIB_PATH="${3:-}"
if [[ -z "$LIB_PATH" ]]; then
  echo "Building unstripped host library for uniffi metadata..."
  cargo build --lib --manifest-path "$RUST_SDK_DIR/Cargo.toml"
  TARGET_DIR="${CARGO_TARGET_DIR:-$RUST_SDK_DIR/target}"
  for candidate in \
    "$TARGET_DIR/debug/lib${CRATE_NAME}.so" \
    "$TARGET_DIR/debug/lib${CRATE_NAME}.dylib"; do
    if [[ -f "$candidate" ]]; then
      LIB_PATH="$candidate"
      break
    fi
  done
fi
if [[ -z "$LIB_PATH" || ! -f "$LIB_PATH" ]]; then
  echo "ERROR: built library not found (pass it as the 3rd argument)" >&2
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

cargo run --quiet --manifest-path "$BINDGEN_MANIFEST" -- \
  generate "$LIB_PATH" \
  --library \
  --crate "$CRATE_NAME" \
  --language "$LANGUAGE" \
  --config "$CONFIG_PATH" \
  -o "$OUT_DIR"

case "$LANGUAGE" in
  kotlin)
    GENERATED="$OUT_DIR/com/utexo/minimalsdk/${CRATE_NAME}.kt"
    ;;
  swift)
    GENERATED="$OUT_DIR/$SWIFT_MODULE.swift"
    ;;
esac
if [[ ! -f "$GENERATED" ]]; then
  echo "ERROR: expected generated file missing: $GENERATED" >&2
  exit 1
fi

if [[ "$LANGUAGE" == "swift" ]]; then
  HEADER="$OUT_DIR/$SWIFT_FFI_MODULE.h"
  MODULEMAP="$OUT_DIR/$SWIFT_FFI_MODULE.modulemap"
  for f in "$HEADER" "$MODULEMAP"; do
    [[ -f "$f" ]] || {
      echo "ERROR: expected generated file missing: $f" >&2
      exit 1
    }
  done
  # A systemLibrary target and an XCFramework headers directory both want
  # the modulemap under its canonical name, next to the header it declares.
  rm -rf "$SWIFT_FFI_DIR"
  mkdir -p "$SWIFT_FFI_DIR"
  mv "$HEADER" "$SWIFT_FFI_DIR/$SWIFT_FFI_MODULE.h"
  mv "$MODULEMAP" "$SWIFT_FFI_DIR/module.modulemap"
  echo "Swift FFI header and modulemap in $SWIFT_FFI_DIR"
fi

echo "Generated $LANGUAGE bindings from $LIB_PATH into $OUT_DIR"
