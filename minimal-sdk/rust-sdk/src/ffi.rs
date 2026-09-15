//! The exported free-function surface. Exported *objects* (`ClientKeys`) keep
//! their `#[uniffi::export] impl` block next to the type, in their own module.
//!
//! Every exported function must return a plain value or [`crate::SdkResult`]
//! and must never panic on caller-controlled input: a panic here becomes a
//! host-app crash (uniffi turns it into a foreign exception at best).
//!
//! Bindings are generated in **library mode** (`uniffi-bindgen generate
//! <built lib> --library`); there is no UDL file and none may be added.
//! `uniffi::setup_scaffolding!()` lives in `lib.rs` because uniffi requires
//! it at the crate root.
//!
//! Generate bindings from an **unstripped host build** (`cargo build --lib`,
//! i.e. `target/debug/libutexo_minimal_sdk.so`): library mode reads the
//! `UNIFFI_META_*` entries from the ELF `.symtab`, which the release profile's
//! `strip = "symbols"` removes. The metadata is profile- and target-independent,
//! so bindings generated from the debug host build match the stripped release
//! and cross-compiled libraries exactly.

use crate::derive::{derive_taproot, parse_account_xpub, DerivedScript};
use crate::invoice::{Bolt11Invoice, RgbInvoice};
use crate::keys::{ClientKeys, GeneratedKeys};
use crate::network::BitcoinNetwork;
use crate::sign::SignResult;
use crate::verify::{VerifyParams, VerifyVerdict};
use crate::SdkResult;
use std::sync::Arc;

/// Version of this SDK core, from `Cargo.toml`. Trivial export used to prove
/// the binding pipeline end to end (Kotlin/Swift smoke tests call it first).
#[uniffi::export]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Generate a fresh 12-word mnemonic and the keys derived from it. The
/// returned mnemonic is the user's only backup: show it once, never send it.
#[uniffi::export]
pub fn generate_keys(network: BitcoinNetwork) -> SdkResult<GeneratedKeys> {
    ClientKeys::generate(network)
}

/// Re-derive the taproot `tr(key)` script and address at `keychain/index`
/// under an **account xpub** (public material only). This is how the app
/// produces receive addresses locally and how it can cross-check an address
/// the gateway hands back. `InvalidInput` when the xpub is malformed or
/// serialized for another network; `DerivationFailed` on a hardened
/// `keychain`/`index`.
#[uniffi::export]
pub fn derive_taproot_address(
    account_xpub: String,
    keychain: u32,
    index: u32,
    network: BitcoinNetwork,
) -> SdkResult<DerivedScript> {
    let xpub = parse_account_xpub(&account_xpub, network)?;
    derive_taproot(&xpub, keychain, index, network)
}

/// Run the five verify-before-sign checks on a base64 PSBT against the
/// gateway's intent summary and the user's own xpubs. Never fails and never
/// panics: hostile or unparseable input is a verdict with every check failed
/// and the reason in each `detail`. Signing (`verify_and_sign_psbt`) runs
/// this internally and refuses on any failure; call it directly to show the
/// user what they are about to approve.
#[uniffi::export(name = "verify_psbt")]
pub fn ffi_verify_psbt(psbt: String, params: VerifyParams) -> VerifyVerdict {
    crate::verify::verify_psbt(&psbt, &params)
}

/// Verify the PSBT against the intent, then BIP-341 key-path sign every
/// input and finalize. The **only** signing entry point: verification runs
/// inside and `VerificationFailed` (naming the failed checks) is returned
/// before anything is signed. `params.xpubs` must be `keys.xpubs()`.
/// Returns the signed+finalized base64 PSBT, its txid and the passing verdict.
#[uniffi::export(name = "verify_and_sign_psbt")]
pub fn ffi_verify_and_sign_psbt(
    keys: Arc<ClientKeys>,
    psbt: String,
    params: VerifyParams,
) -> SdkResult<SignResult> {
    crate::sign::verify_and_sign_psbt(&keys, &psbt, &params)
}

/// Decode a BOLT-11 lightning invoice (network, amount, payment hash and
/// secret, description, recovered payee, timestamp, expiry). Fed user-pasted
/// strings: any malformed input is `InvoiceDecode`, never a panic.
#[uniffi::export(name = "decode_bolt11")]
pub fn ffi_decode_bolt11(invoice: String) -> SdkResult<Bolt11Invoice> {
    crate::invoice::decode_bolt11(&invoice)
}

/// Decode an RGB invoice (rgb-invoicing v0.11 grammar, `~` = omitted
/// segment): asset id, amount, chain-qualified recipient id, beneficiary
/// kind, transport endpoints, expiry. Malformed input is `InvoiceDecode`.
#[uniffi::export(name = "decode_rgb_invoice")]
pub fn ffi_decode_rgb_invoice(invoice: String) -> SdkResult<RgbInvoice> {
    crate::invoice::decode_rgb_invoice(&invoice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_version_matches_manifest() {
        assert_eq!(sdk_version(), env!("CARGO_PKG_VERSION"));
        assert!(!sdk_version().is_empty());
    }
}
