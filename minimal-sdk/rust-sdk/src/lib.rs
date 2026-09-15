//! Minimal UTEXO client SDK core.
//!
//! One Rust implementation of key management, taproot derivation,
//! verify-before-sign PSBT checks, signing, invoice decoding and the gateway
//! client, exposed to Kotlin and Swift through uniffi. This crate is **not**
//! the node: no LDK, no rgb-lib, no HTTP or TLS stack.
//!
//! Behavioural reference: `minimal-sdk/packages/client-sdk/src/` (TypeScript).
//! Parity against rgb-lib is checked in `tests/parity.rs` from the fixture
//! `minimal-sdk/packages/client-sdk/test/fixtures/rgblib-parity.json`.
//!
//! Invariants that hold everywhere in this crate (design doc I1–I4):
//! - the mnemonic and any xprv never leave the device and are never a gateway
//!   request field;
//! - only account xpubs and the master fingerprint are ever sent to the gateway;
//! - nothing logs, `Debug`-prints or renders a mnemonic, seed, xprv or private
//!   key, including error variants;
//! - no panic crosses the FFI boundary: every exported function returns
//!   [`SdkResult`].

use std::sync::OnceLock;

use bitcoin::secp256k1::{All, Secp256k1};

uniffi::setup_scaffolding!();

pub mod derive;
pub mod ffi;
pub mod gateway;
pub mod invoice;
pub(crate) mod json;
pub mod keys;
pub mod network;
pub mod sign;
pub mod verify;

pub use derive::{
    derive_for_origin_path, derive_taproot, match_origin_path, parse_account_xpub, DerivedScript,
    OriginPathMatch, ParsedAccounts,
};
pub use ffi::{derive_taproot_address, generate_keys, sdk_version};
pub use gateway::{
    encode_uri_component, generate_idempotency_key, GatewayClient, HttpMethod, HttpRequest,
    HttpResponse, HttpTransport, PreparedOp,
};
pub use invoice::{decode_bolt11, decode_rgb_invoice, BeneficiaryKind, Bolt11Invoice, RgbInvoice};
pub use keys::{AccountXpubs, ClientKeys, GeneratedKeys};
pub use network::BitcoinNetwork;
pub use sign::{verify_and_sign_psbt, SignResult};
pub use verify::{
    own_derivation, verify_psbt, CheckName, CheckResult, IntentAsset, IntentKind, IntentRecipient,
    IntentUtxos, OnchainIntent, TapKeyOrigins, VerifyParams, VerifyVerdict,
};

/// Process-wide secp256k1 context (signing + verification). Built once; the
/// precomputed tables are the bulk of the crate's size and are shared.
pub(crate) fn secp() -> &'static Secp256k1<All> {
    static SECP: OnceLock<Secp256k1<All>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::new)
}

/// The single error type every exported function returns.
///
/// Variants carry only diagnostic strings and status codes. **Never** format a
/// mnemonic, seed, xprv, private key, or raw PSBT/transaction bytes derived from
/// them into a variant: errors are the place secrets leak in practice, and the
/// host app may log them verbatim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum SdkError {
    /// A caller-supplied argument was malformed (bad network name, bad hex, ...).
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    /// The mnemonic did not pass BIP-39 validation. Deliberately carries no
    /// detail about the words supplied.
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    /// A BIP-32 / taproot derivation failed (hardened path requested from an
    /// xpub, index out of range, ...).
    #[error("derivation failed: {reason}")]
    DerivationFailed { reason: String },
    /// The PSBT could not be parsed at all. Hostile-but-parseable PSBTs are a
    /// failed verification verdict, not an error.
    #[error("invalid psbt: {reason}")]
    InvalidPsbt { reason: String },
    /// One of the five verify-before-sign checks failed; signing was refused.
    #[error("verification failed at check '{check}': {reason}")]
    VerificationFailed { check: String, reason: String },
    /// Signing or finalization failed after verification passed.
    #[error("signing failed: {reason}")]
    SigningFailed { reason: String },
    /// A BOLT-11 or RGB invoice could not be decoded. The only error the
    /// invoice decoders return: they are fed user-pasted strings.
    #[error("invalid invoice: {reason}")]
    InvoiceDecode { reason: String },
    /// The foreign HTTP transport reported a failure (no HTTP status available).
    #[error("transport error: {reason}")]
    Transport { reason: String },
    /// The gateway answered with a non-success status. `detail` is the
    /// server's human-readable message (`{ error: { message } }` in the
    /// body). It is deliberately not named `message`: uniffi renders error
    /// variants as `kotlin.Exception` subclasses, where a `message` field
    /// collides with `Throwable.message` and the generated Kotlin does not
    /// compile (found by the Task 8 Android build).
    #[error("gateway error {status}: {code}: {detail}")]
    Gateway {
        status: u16,
        code: String,
        detail: String,
    },
    /// The gateway's returned intent did not match what the client asked for.
    #[error("intent mismatch: {reason}")]
    IntentMismatch { reason: String },
    /// An internal invariant was violated. Reported instead of panicking so the
    /// host app gets an error rather than a crash.
    #[error("internal error: {reason}")]
    Internal { reason: String },
}

/// Result alias every exported function returns.
pub type SdkResult<T> = Result<T, SdkError>;

/// A foreign `HttpTransport` that throws anything other than the declared
/// `SdkError` (a Kotlin `RuntimeException`, a Swift `Error` that is not
/// `SdkError`, a failure to lift the error buffer) reaches Rust as
/// `UnexpectedUniFFICallbackError`. Without this conversion uniffi's generic
/// path panics inside `GatewayClient`, which the export boundary re-raises as
/// an untyped internal exception: the one place a host bug would break the
/// "no panic crosses the FFI" invariant. Mapping it to `Transport` keeps the
/// error typed; `reason` is uniffi's own diagnostic and carries no headers.
impl From<uniffi::UnexpectedUniFFICallbackError> for SdkError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        SdkError::Transport {
            reason: format!("transport raised an unexpected error: {}", e.reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_carries_only_diagnostics() {
        let err = SdkError::VerificationFailed {
            check: "fee-budget".into(),
            reason: "fee 1200 > max 1000".into(),
        };
        assert_eq!(
            err.to_string(),
            "verification failed at check 'fee-budget': fee 1200 > max 1000"
        );
        assert_eq!(SdkError::InvalidMnemonic.to_string(), "invalid mnemonic");
    }

    #[test]
    fn unexpected_foreign_callback_errors_become_transport_errors() {
        let err: SdkError = uniffi::UnexpectedUniFFICallbackError::new("boom").into();
        assert_eq!(
            err,
            SdkError::Transport {
                reason: "transport raised an unexpected error: boom".into()
            }
        );
    }
}
