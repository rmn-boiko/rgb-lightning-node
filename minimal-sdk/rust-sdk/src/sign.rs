//! BIP-341 key-path sign + finalize. Refuses to sign unless verify-before-sign
//! passed: verification runs **inside** [`verify_and_sign_psbt`] and a failed
//! verdict is [`SdkError::VerificationFailed`] — there is no bypass. This
//! module exports exactly one function and no flag, second entry point or
//! `pub` helper that signs without verifying (asserted in `tests/parity.rs`).
//!
//! Keys are derived per input from the PSBT's own key-origin paths, but only
//! after [`crate::verify`] check 1 proved each path re-derives to the exact
//! script being spent, and only from the entry [`own_derivation`] selects by
//! our master fingerprint — the same entry check 1 proved.
//!
//! Behavioural reference: `minimal-sdk/packages/client-sdk/src/sign.ts`.
//! Parity with rgb-lib's own signer is **txid + signature validity**, never
//! witness byte-equality: BIP-340 signatures are randomized.

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, XOnlyPublicKey};
use bitcoin::psbt::Psbt;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot;
use bitcoin::{TapSighashType, TxOut, Witness};

use crate::keys::ClientKeys;
use crate::verify::{own_derivation, verify_psbt, VerifyParams, VerifyVerdict};
use crate::{secp, SdkError, SdkResult};

/// What [`verify_and_sign_psbt`] returns on success.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignResult {
    /// Signed AND finalized PSBT, base64 — what the gateway's `complete`
    /// expects.
    pub signed_psbt: String,
    pub txid: String,
    /// The passing verdict signing was conditioned on.
    pub verdict: VerifyVerdict,
}

/// Verify the PSBT against the intent, then key-path-sign every input and
/// finalize.
///
/// Errors, in order of evaluation:
/// - `InvalidInput` when `params.xpubs` are not the xpubs of `keys`: the
///   verdict would then be proven for a different wallet than the one
///   signing, breaking "sign with the entry verify proved". Checked first
///   because it is a caller bug, not a property of the PSBT.
/// - `VerificationFailed` when any of the five checks fails: `check` names
///   the first failed check, `reason` lists every failed check with its
///   detail. Nothing is signed.
/// - `SigningFailed` naming the input index when an input has no signable
///   key-origin entry of ours (never a skip), carries a sighash type other
///   than `DEFAULT`/`ALL` (a `NONE`/`SINGLE`/`ANYONECANPAY` signature would
///   not commit to the outputs the verdict approved), or the produced
///   signature does not verify against the script being spent.
///
/// No error carries key material; every reason is an input index, a check
/// name or a fixed diagnostic.
pub fn verify_and_sign_psbt(
    keys: &ClientKeys,
    psbt_base64: &str,
    params: &VerifyParams,
) -> SdkResult<SignResult> {
    // The verdict is proven against `params.xpubs`; the signature comes
    // from `keys`. They must be the same wallet, or check 1's "this path
    // re-derives to the spent script" says nothing about the key used below.
    if params.xpubs != keys.xpubs() {
        return Err(SdkError::InvalidInput {
            reason: "params.xpubs are not the xpubs of the signing keys".into(),
        });
    }
    let verdict = verify_psbt(psbt_base64, params);
    if !verdict.ok {
        return Err(refusal(&verdict));
    }

    let mut psbt: Psbt = psbt_base64.parse().map_err(|_| SdkError::InvalidPsbt {
        reason: "psbt did not re-parse after verification".into(),
    })?;
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    if verdict.txid.as_deref() != Some(txid.as_str()) {
        return Err(SdkError::Internal {
            reason: "verdict txid does not match the transaction being signed".into(),
        });
    }

    // Check 1 guarantees every input carries a witness_utxo; collect them
    // once for the BIP-341 sighash (which commits to all prevouts).
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input.witness_utxo.clone().ok_or(SdkError::SigningFailed {
                reason: format!("input {i}: no witnessUtxo"),
            })
        })
        .collect::<SdkResult<_>>()?;
    let prevouts = Prevouts::All(&prevouts);
    let mut cache = SighashCache::new(&psbt.unsigned_tx);

    let mut signatures: Vec<taproot::Signature> = Vec::with_capacity(psbt.inputs.len());
    for (index, input) in psbt.inputs.iter().enumerate() {
        // Sign with the SAME entry verify proved re-derives to the script
        // being spent — selected by our master fingerprint, not by path
        // shape. Matching on shape alone would pick a decoy entry carrying a
        // foreign fingerprint when the PSBT lists one first, and signing
        // would then fail against a key no check ever covered.
        let Some((_, source)) = own_derivation(&input.tap_key_origins, keys.fingerprint()) else {
            return Err(SdkError::SigningFailed {
                reason: format!("input {index}: no signable key-origin path"),
            });
        };
        let Some(secret_key) = keys.private_key_for_path(&source.1.to_u32_vec()) else {
            return Err(SdkError::SigningFailed {
                reason: format!("input {index}: key-origin path is not under our accounts"),
            });
        };

        // Only DEFAULT (absent) or ALL: anything else would let the
        // transaction be altered after the verdict approved it.
        let sighash_type = match input.sighash_type {
            None => TapSighashType::Default,
            Some(ty) => match ty.taproot_hash_ty() {
                Ok(TapSighashType::Default) => TapSighashType::Default,
                Ok(TapSighashType::All) => TapSighashType::All,
                _ => {
                    return Err(SdkError::SigningFailed {
                        reason: format!("input {index}: unsupported sighash type {ty}"),
                    })
                }
            },
        };
        let sighash = cache
            .taproot_key_spend_signature_hash(index, &prevouts, sighash_type)
            .map_err(|_| SdkError::SigningFailed {
                reason: format!("input {index}: sighash computation failed"),
            })?;
        let message = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());

        // BIP-341 key-path spend of a `tr(key)` output with no script tree:
        // tweak the derived internal key with an empty merkle root — the
        // construction check 1 re-derived the spent script from.
        let keypair = Keypair::from_secret_key(secp(), &secret_key)
            .tap_tweak(secp(), None)
            .to_keypair();
        let signature = secp().sign_schnorr(&message, &keypair);

        // End-to-end proof the signature spends THIS output: verify it
        // against the output key inside the spent script, not against
        // anything the PSBT metadata claims.
        let output_key = spent_output_key(&input.witness_utxo).ok_or(SdkError::SigningFailed {
            reason: format!("input {index}: spent script is not a taproot output"),
        })?;
        if secp()
            .verify_schnorr(&signature, &message, &output_key)
            .is_err()
        {
            return Err(SdkError::SigningFailed {
                reason: format!(
                    "input {index}: signature does not verify against the spent script"
                ),
            });
        }
        signatures.push(taproot::Signature {
            signature,
            sighash_type,
        });
    }

    // Signer role: record every key-path signature on its input.
    for (input, signature) in psbt.inputs.iter_mut().zip(signatures) {
        input.tap_key_sig = Some(signature);
    }
    // Finalizer role: build the one-element key-path witness from
    // tap_key_sig and, as BIP-174 requires, drop the signing metadata the
    // final witness supersedes. Only the UTXO fields and the final witness
    // stay — exactly what rgb-lib's own finalized fixture PSBT retains.
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let signature = input.tap_key_sig.take().ok_or(SdkError::Internal {
            reason: format!("input {index}: signed but no tap_key_sig to finalize"),
        })?;
        input.final_script_witness = Some(Witness::p2tr_key_spend(&signature));
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation.clear();
        input.tap_script_sigs.clear();
        input.tap_scripts.clear();
        input.tap_key_origins.clear();
        input.tap_internal_key = None;
        input.tap_merkle_root = None;
    }

    Ok(SignResult {
        signed_psbt: psbt.to_string(),
        txid,
        verdict,
    })
}

/// The 32-byte output key of a `OP_1 <32 bytes>` script, if that is what
/// the spent output is.
fn spent_output_key(witness_utxo: &Option<TxOut>) -> Option<XOnlyPublicKey> {
    let script = witness_utxo.as_ref()?.script_pubkey.as_bytes();
    if !(script.len() == 34 && script[0] == 0x51 && script[1] == 0x20) {
        return None;
    }
    XOnlyPublicKey::from_slice(&script[2..]).ok()
}

/// The refusal error for a failed verdict: `check` is the first failed
/// check, `reason` lists every failed check with its detail (which carry
/// indexes, amounts, addresses and check names only — never key material).
fn refusal(verdict: &VerifyVerdict) -> SdkError {
    let failed: Vec<String> = verdict
        .checks
        .iter()
        .filter(|c| !c.ok)
        .map(|c| match &c.detail {
            Some(detail) => format!("{} ({detail})", c.check),
            None => c.check.to_string(),
        })
        .collect();
    SdkError::VerificationFailed {
        check: verdict
            .first_failure()
            .map(|c| c.check.to_string())
            .unwrap_or_default(),
        reason: format!("refusing to sign: {}", failed.join("; ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{CheckName, CheckResult};

    #[test]
    fn refusal_names_the_first_failure_and_lists_them_all() {
        let verdict = VerifyVerdict {
            ok: false,
            checks: CheckName::ALL
                .iter()
                .map(|&check| CheckResult {
                    check,
                    ok: !matches!(check, CheckName::RecipientsMatch | CheckName::FeeBudget),
                    detail: match check {
                        CheckName::RecipientsMatch => Some("no output pays 39000 sat".into()),
                        CheckName::FeeBudget => Some("fee 5000 sat outside budget".into()),
                        _ => None,
                    },
                })
                .collect(),
            fee_sat: Some(5000),
            txid: None,
        };
        let err = refusal(&verdict);
        assert_eq!(
            err,
            SdkError::VerificationFailed {
                check: "recipients-match".into(),
                reason: "refusing to sign: recipients-match (no output pays 39000 sat); \
                         fee-budget (fee 5000 sat outside budget)"
                    .into(),
            }
        );
    }

    #[test]
    fn spent_output_key_accepts_only_p2tr_scripts() {
        let key = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let p2tr = bitcoin::ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(key),
        );
        let utxo = |script: bitcoin::ScriptBuf| {
            Some(TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: script,
            })
        };
        assert_eq!(spent_output_key(&utxo(p2tr)), Some(key));
        assert_eq!(spent_output_key(&None), None);
        assert_eq!(spent_output_key(&utxo(bitcoin::ScriptBuf::new())), None);
        // P2WPKH (OP_0 <20 bytes>) and a 33-byte OP_1 push are not taproot.
        assert_eq!(
            spent_output_key(&utxo(bitcoin::ScriptBuf::from_bytes(
                [vec![0x00, 0x14], vec![7u8; 20]].concat()
            ))),
            None
        );
        assert_eq!(
            spent_output_key(&utxo(bitcoin::ScriptBuf::from_bytes(
                [vec![0x51, 0x21], vec![2u8; 33]].concat()
            ))),
            None
        );
    }
}
