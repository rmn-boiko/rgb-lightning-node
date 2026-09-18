//! Verify-before-sign: the design doc's five checks, evaluated against a
//! parsed PSBT and the gateway's machine-readable intent summary. Signing is
//! never blind — `sign` refuses unless the verdict here is ok.
//!
//! All PSBT content (scripts, amounts, key-origin metadata) is treated as
//! adversarial. Ownership is proven by **re-deriving** scripts from the
//! user's own account xpubs: a hostile server may supply any path it likes,
//! but only a path under the user's accounts can re-derive to a script the
//! user controls. [`verify_psbt`] never returns an error and never panics on
//! malformed input — it returns a failed verdict.
//!
//! Known limitation (design doc, "send-time trust"): RGB allocations on the
//! spent inputs are NOT verifiable here; only bitcoin-value movement is.
//!
//! Behavioural reference: `minimal-sdk/packages/client-sdk/src/verify.ts`.
//! Two properties from that source must survive any refactor:
//!
//! 1. [`own_derivation`] selects the key-origin entry **by our master
//!    fingerprint, never by path shape**, and sign signs with the very entry
//!    verify proved.
//! 2. Own **outputs** are restricted to keychain 0 at a bounded index; own
//!    **inputs** are not. The asymmetry is deliberate (see check 3).

use std::cell::OnceCell;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::str::FromStr;

use bitcoin::bip32::{Fingerprint, KeySource};
use bitcoin::hex::DisplayHex;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::taproot::TapLeafHash;
use bitcoin::Address;

use crate::derive::{derive_for_origin_path, derive_taproot, ParsedAccounts};
use crate::keys::AccountXpubs;
use crate::network::{BitcoinNetwork, KEYCHAIN};

/// Which gateway operation an intent summarises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum IntentKind {
    SendBtc,
    SendAsset,
    CreateUtxos,
}

impl IntentKind {
    /// The gateway's wire name (`send_btc`, `send_asset`, `create_utxos`).
    pub fn name(self) -> &'static str {
        match self {
            IntentKind::SendBtc => "send_btc",
            IntentKind::SendAsset => "send_asset",
            IntentKind::CreateUtxos => "create_utxos",
        }
    }

    /// Inverse of [`IntentKind::name`], for decoding a gateway response.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "send_btc" => Some(IntentKind::SendBtc),
            "send_asset" => Some(IntentKind::SendAsset),
            "create_utxos" => Some(IntentKind::CreateUtxos),
            _ => None,
        }
    }
}

impl fmt::Display for IntentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A bitcoin recipient in the gateway's intent summary. Mirrors the
/// gateway's prepare-response schema (kept in sync).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IntentRecipient {
    /// Human-readable address — the field the user actually reviews and the
    /// one check 2 re-derives the expected script from.
    pub address: String,
    /// Server-supplied output script, lowercase hex. Only cross-checked
    /// against the address; never trusted on its own.
    pub script_hex: String,
    pub amount_sat: u64,
}

/// The RGB side of a `send_asset` intent.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IntentAsset {
    pub asset_id: String,
    pub amount: u64,
    pub recipient_id: String,
    /// `Some` for witness (`wvout`) beneficiaries: the exact sat amount the
    /// one foreign witness output must carry. `None` for blind sends, where
    /// no foreign output is allowed at all.
    pub witness_amount_sat: Option<u64>,
    pub transport_endpoints: Vec<String>,
}

/// The shape of a `create_utxos` intent.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IntentUtxos {
    pub up_to: bool,
    pub num: u32,
    pub size: u64,
}

/// The gateway's machine-readable summary of what a prepared PSBT does.
///
/// It is SERVER-produced. The caller must bind it to the user's own request
/// first (the gateway client's `prepare*` methods do); check 2 is only as
/// trustworthy as that binding.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OnchainIntent {
    pub kind: IntentKind,
    pub fee_rate_sat_per_vb: u64,
    pub recipients: Vec<IntentRecipient>,
    pub asset: Option<IntentAsset>,
    pub utxos: Option<IntentUtxos>,
}

/// The five verify-before-sign checks, in evaluation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum CheckName {
    InputsOwn,
    RecipientsMatch,
    ChangeOwn,
    FeeBudget,
    OpretZero,
}

impl CheckName {
    /// All five checks, in the order every verdict lists them.
    pub const ALL: [CheckName; 5] = [
        CheckName::InputsOwn,
        CheckName::RecipientsMatch,
        CheckName::ChangeOwn,
        CheckName::FeeBudget,
        CheckName::OpretZero,
    ];

    /// The check's wire name, identical to the TypeScript SDK's `CheckName`.
    pub fn name(self) -> &'static str {
        match self {
            CheckName::InputsOwn => "inputs-own",
            CheckName::RecipientsMatch => "recipients-match",
            CheckName::ChangeOwn => "change-own",
            CheckName::FeeBudget => "fee-budget",
            CheckName::OpretZero => "opret-zero",
        }
    }
}

impl fmt::Display for CheckName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CheckResult {
    pub check: CheckName,
    pub ok: bool,
    /// Human-readable reason when `ok` is false. Carries indexes, amounts,
    /// addresses and check names only — never key material.
    pub detail: Option<String>,
}

/// The verdict: `ok` only when all five checks pass.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VerifyVerdict {
    pub ok: bool,
    /// Exactly five entries, in [`CheckName::ALL`] order.
    pub checks: Vec<CheckResult>,
    /// Absolute fee in sats (`inputs − outputs`), when computable. Negative
    /// when the outputs exceed the inputs.
    pub fee_sat: Option<i64>,
    /// Txid of the unsigned transaction, when parseable.
    pub txid: Option<String>,
}

impl VerifyVerdict {
    /// The result of one named check.
    pub fn check(&self, name: CheckName) -> Option<&CheckResult> {
        self.checks.iter().find(|c| c.check == name)
    }

    /// Names of the checks that failed, in evaluation order.
    pub fn failed(&self) -> Vec<CheckName> {
        self.checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| c.check)
            .collect()
    }

    /// The first failed check, if any — what a refusal error reports.
    pub fn first_failure(&self) -> Option<&CheckResult> {
        self.checks.iter().find(|c| !c.ok)
    }
}

/// Everything [`verify_psbt`] needs besides the PSBT itself.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VerifyParams {
    /// Intent summary from the prepare response, already bound to the
    /// user's own request.
    pub intent: OnchainIntent,
    /// The user's own account xpubs + master fingerprint
    /// ([`crate::keys::ClientKeys::xpubs`]).
    pub xpubs: AccountXpubs,
    /// User-approved absolute fee budget in sats (check 4).
    pub max_fee_sat: u64,
    /// Fallback for own outputs lacking key-origin metadata: accept scripts
    /// re-derived at keychain 0, indexes `0..window`, on both accounts.
    /// `Some(0)` disables the fallback (metadata-only). `None` = 30.
    #[uniffi(default = None)]
    pub change_scan_window: Option<u32>,
    /// Highest derivation index accepted for a metadata-proven own OUTPUT
    /// (check 3). Any index under the account xpub re-derives, but only
    /// indexes a descriptor wallet will actually scan are recoverable —
    /// without this bound a hostile gateway could steer "change" to e.g.
    /// index 9e8, where the funds are technically the user's yet invisible
    /// to every wallet scan. Kept far above realistic per-user usage while
    /// cheap to sweep in a recovery scan. `None` = 10 000.
    #[uniffi(default = None)]
    pub max_own_output_index: Option<u32>,
}

/// Default for [`VerifyParams::change_scan_window`].
pub const DEFAULT_CHANGE_SCAN_WINDOW: u32 = 30;
/// Default for [`VerifyParams::max_own_output_index`].
pub const DEFAULT_MAX_OWN_OUTPUT_INDEX: u32 = 10_000;

/// The taproot key-origin map a PSBT input or output carries, keyed by
/// x-only public key (so distinct decoy keys are distinct entries).
pub type TapKeyOrigins = BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>;

/// First key-origin entry carrying the user's master fingerprint, if any:
/// the x-only key it is filed under and its `(fingerprint, path)` source.
///
/// Public because sign MUST pick the signing key from the very entry this
/// proved: selecting by path *shape* alone would let a decoy entry with a
/// foreign fingerprint, ordered first, divert signing to a key the verdict
/// never covered. The path inside the returned entry is still
/// attacker-controlled and is only ever accepted through
/// [`crate::derive::match_origin_path`].
pub fn own_derivation(
    origins: &TapKeyOrigins,
    fingerprint: Fingerprint,
) -> Option<(XOnlyPublicKey, &KeySource)> {
    origins
        .iter()
        .find(|(_, (_, source))| source.0 == fingerprint)
        .map(|(key, (_, source))| (*key, source))
}

/// One transaction output as the checks see it.
struct ParsedOutput {
    index: usize,
    script_hex: String,
    amount_sat: u64,
    is_opret: bool,
    /// Proven ours by re-derivation (metadata path or scan window).
    is_own: bool,
}

/// Output script (lowercase hex) for an address on `network`, or `None`
/// when it does not decode there.
fn script_hex_from_address(address: &str, network: BitcoinNetwork) -> Option<String> {
    let parsed = Address::from_str(address).ok()?;
    let checked = parsed.require_network(network.to_bitcoin()).ok()?;
    Some(checked.script_pubkey().to_hex_string())
}

fn fail_all(detail: &str) -> VerifyVerdict {
    VerifyVerdict {
        ok: false,
        checks: CheckName::ALL
            .iter()
            .map(|&check| CheckResult {
                check,
                ok: false,
                detail: Some(detail.to_owned()),
            })
            .collect(),
        fee_sat: None,
        txid: None,
    }
}

fn result(check: CheckName, failures: Vec<String>) -> CheckResult {
    CheckResult {
        check,
        ok: failures.is_empty(),
        detail: if failures.is_empty() {
            None
        } else {
            Some(failures.join("; "))
        },
    }
}

/// Run the five checks. **Never** returns an error and never panics: a PSBT
/// that cannot be parsed, an xpub or fingerprint that cannot be read, or an
/// internal failure of any kind yields a verdict with all five checks failed
/// and the reason in every `detail`.
pub fn verify_psbt(psbt: &str, params: &VerifyParams) -> VerifyVerdict {
    // Belt and braces: every line below is written not to panic on hostile
    // input, but a panic here would be a host-app crash, so the whole
    // evaluation is fenced as well.
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify_parsed(psbt, params)));
    match outcome {
        Ok(Ok(verdict)) => verdict,
        Ok(Err(reason)) => fail_all(&format!("psbt could not be safely parsed: {reason}")),
        Err(_) => fail_all("psbt could not be safely parsed: internal failure"),
    }
}

fn verify_parsed(psbt: &str, params: &VerifyParams) -> Result<VerifyVerdict, String> {
    let intent = &params.intent;
    let network = params.xpubs.network;
    let our_fingerprint = Fingerprint::from_str(&params.xpubs.fingerprint)
        .map_err(|_| "master fingerprint is not 8 hex chars".to_owned())?;
    let accounts = ParsedAccounts::parse(&params.xpubs).map_err(|e| e.to_string())?;
    let psbt = Psbt::from_str(psbt).map_err(|e| e.to_string())?;
    let mut checks: Vec<CheckResult> = Vec::with_capacity(CheckName::ALL.len());

    // Check 1 — every input is ours: key-origin fingerprint matches AND the
    // path re-derives (from OUR xpubs) to the exact script being spent.
    let mut input_failures: Vec<String> = Vec::new();
    let mut input_total_sat: u128 = 0;
    for (i, input) in psbt.inputs.iter().enumerate() {
        let Some(utxo) = &input.witness_utxo else {
            input_failures.push(format!(
                "input {i}: no witnessUtxo, cannot verify what is being spent"
            ));
            continue;
        };
        input_total_sat += u128::from(utxo.value.to_sat());
        let Some((_, source)) = own_derivation(&input.tap_key_origins, our_fingerprint) else {
            input_failures.push(format!(
                "input {i}: no key origin with our fingerprint (foreign input)"
            ));
            continue;
        };
        let Some(derived) = derive_for_origin_path(&source.1.to_u32_vec(), &accounts, network)
        else {
            input_failures.push(format!(
                "input {i}: key-origin path is not under our accounts"
            ));
            continue;
        };
        if derived.script_hex != utxo.script_pubkey.to_hex_string() {
            input_failures.push(format!(
                "input {i}: spent script does not re-derive from our keys"
            ));
            continue;
        }
        if let Some(internal_key) = input.tap_internal_key {
            if internal_key.serialize().to_lower_hex_string() != derived.internal_key_hex {
                input_failures.push(format!(
                    "input {i}: tapInternalKey mismatch with re-derived key"
                ));
            }
        }
    }
    if psbt.inputs.is_empty() {
        input_failures.push("transaction has no inputs".to_owned());
    }
    checks.push(result(CheckName::InputsOwn, input_failures));

    // Own-script set for the metadata-less change fallback (keychain 0 only —
    // the single keychain rgb-lib uses on both accounts). Built lazily: real
    // rgb-lib PSBTs carry key-origin metadata on their change outputs, so the
    // common path must not pay for 2 × scan_window key derivations.
    let scan_window = params
        .change_scan_window
        .unwrap_or(DEFAULT_CHANGE_SCAN_WINDOW);
    let scanned_own_scripts: OnceCell<HashSet<String>> = OnceCell::new();
    let is_scanned_own_script = |script_hex: &str| {
        scanned_own_scripts
            .get_or_init(|| {
                let mut set = HashSet::new();
                for account in [&accounts.vanilla, &accounts.colored] {
                    for index in 0..scan_window {
                        if let Ok(derived) = derive_taproot(account, KEYCHAIN, index, network) {
                            set.insert(derived.script_hex);
                        }
                    }
                }
                set
            })
            .contains(script_hex)
    };
    let max_own_output_index = params
        .max_own_output_index
        .unwrap_or(DEFAULT_MAX_OWN_OUTPUT_INDEX);

    let mut outputs: Vec<ParsedOutput> = Vec::with_capacity(psbt.outputs.len());
    let mut output_total_sat: u128 = 0;
    for (index, (txout, output)) in psbt
        .unsigned_tx
        .output
        .iter()
        .zip(psbt.outputs.iter())
        .enumerate()
    {
        let script_hex = txout.script_pubkey.to_hex_string();
        let amount_sat = txout.value.to_sat();
        output_total_sat += u128::from(amount_sat);
        let is_opret = txout.script_pubkey.as_bytes().first() == Some(&0x6a);
        let mut is_own = false;
        if let Some((_, source)) = own_derivation(&output.tap_key_origins, our_fingerprint) {
            // Own OUTPUTS must live in the wallet's real descriptor space:
            // keychain 0 (the single keychain rgb-lib scans, `KEYCHAIN`) at a
            // bounded index. Inputs (check 1) stay unrestricted — spending
            // from an odd path is proven safe by the script re-derivation
            // alone. Do not "tidy" this asymmetry.
            is_own = derive_for_origin_path(&source.1.to_u32_vec(), &accounts, network)
                .is_some_and(|derived| {
                    derived.script_hex == script_hex
                        && derived.keychain == KEYCHAIN
                        && derived.index <= max_own_output_index
                });
        }
        if !is_own && !is_opret {
            is_own = is_scanned_own_script(&script_hex);
        }
        outputs.push(ParsedOutput {
            index,
            script_hex,
            amount_sat,
            is_opret,
            is_own,
        });
    }

    // Check 2 — recipient outputs match the user-stated intent
    // (script + amount), matched as a multiset; plus (witness asset sends)
    // exactly one foreign output carrying exactly the approved witness amount.
    //
    // The expected script is RE-DERIVED from the human-readable address — the
    // field the user actually reviews. The server-supplied script_hex is only
    // cross-checked: a hostile gateway could otherwise pair the intended
    // address with an attacker script and both would "match".
    let mut accounted: HashSet<usize> = HashSet::new();
    let mut recipient_failures: Vec<String> = Vec::new();
    for recipient in &intent.recipients {
        let Some(expected_script_hex) = script_hex_from_address(&recipient.address, network) else {
            recipient_failures.push(format!(
                "recipient address {} does not decode on {network}",
                recipient.address
            ));
            continue;
        };
        if recipient.script_hex.to_lowercase() != expected_script_hex {
            recipient_failures.push(format!(
                "intent scriptHex does not match recipient address {}",
                recipient.address
            ));
            continue;
        }
        let matched = outputs.iter().find(|o| {
            !accounted.contains(&o.index)
                && o.script_hex == expected_script_hex
                && o.amount_sat == recipient.amount_sat
        });
        match matched {
            Some(output) => {
                accounted.insert(output.index);
            }
            None => recipient_failures.push(format!(
                "no output pays {} sat to intended recipient {}",
                recipient.amount_sat, recipient.address
            )),
        }
    }
    if let Some(witness_amount) = intent.asset.as_ref().and_then(|a| a.witness_amount_sat) {
        let candidates: Vec<usize> = outputs
            .iter()
            .filter(|o| {
                !accounted.contains(&o.index)
                    && !o.is_own
                    && !o.is_opret
                    && o.amount_sat == witness_amount
            })
            .map(|o| o.index)
            .collect();
        match candidates.as_slice() {
            [only] => {
                accounted.insert(*only);
            }
            _ => recipient_failures.push(format!(
                "expected exactly one witness output of {witness_amount} sat, found {}",
                candidates.len()
            )),
        }
    }
    checks.push(result(CheckName::RecipientsMatch, recipient_failures));

    // Check 3 — change pays only re-derivable own scripts: everything that is
    // not an intended recipient, the approved witness output, or an
    // OP_RETURN must prove ownership.
    let change_failures: Vec<String> = outputs
        .iter()
        .filter(|o| !accounted.contains(&o.index) && !o.is_opret && !o.is_own)
        .map(|o| {
            format!(
                "output {} ({} sat) does not re-derive from our keys",
                o.index, o.amount_sat
            )
        })
        .collect();
    checks.push(result(CheckName::ChangeOwn, change_failures));

    // Check 4 — fee = inputs − outputs within the user-approved budget.
    let fee: i128 = input_total_sat as i128 - output_total_sat as i128;
    let fee_ok = fee > 0 && fee <= i128::from(params.max_fee_sat);
    checks.push(result(
        CheckName::FeeBudget,
        if fee_ok {
            Vec::new()
        } else {
            vec![format!(
                "fee {fee} sat outside budget (0, {}]",
                params.max_fee_sat
            )]
        },
    ));

    // Check 5 — OP_RETURN outputs carry 0 sats.
    let opret_failures: Vec<String> = outputs
        .iter()
        .filter(|o| o.is_opret && o.amount_sat != 0)
        .map(|o| format!("OP_RETURN output {} carries {} sat", o.index, o.amount_sat))
        .collect();
    checks.push(result(CheckName::OpretZero, opret_failures));

    Ok(VerifyVerdict {
        ok: checks.iter().all(|c| c.ok),
        checks,
        fee_sat: i64::try_from(fee).ok(),
        txid: Some(psbt.unsigned_tx.compute_txid().to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{ChildNumber, DerivationPath};

    fn origins(entries: &[(XOnlyPublicKey, Fingerprint, &[u32])]) -> TapKeyOrigins {
        entries
            .iter()
            .map(|(key, fp, path)| {
                let path: DerivationPath = path
                    .iter()
                    .map(|&c| ChildNumber::from(c))
                    .collect::<Vec<_>>()
                    .into();
                (*key, (Vec::new(), (*fp, path)))
            })
            .collect()
    }

    fn xonly(byte: u8) -> XOnlyPublicKey {
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
        let (key, _) = sk.x_only_public_key(crate::secp());
        key
    }

    #[test]
    fn own_derivation_selects_by_fingerprint_not_position_or_shape() {
        let ours = Fingerprint::from([0x73, 0xc5, 0xda, 0x0a]);
        let theirs = Fingerprint::from([1, 2, 3, 4]);
        let our_key = xonly(9);
        let decoy_key = xonly(2);
        let our_path: &[u32] = &[0x8000_0056, 0x8000_0001, 0x8000_0000, 0, 0];
        // The decoy carries a *well-formed* own-looking path and a key that
        // sorts first; only the fingerprint tells them apart.
        let map = origins(&[(decoy_key, theirs, our_path), (our_key, ours, our_path)]);
        assert!(map.keys().next() == Some(&decoy_key) || map.keys().next() == Some(&our_key));
        let (key, source) = own_derivation(&map, ours).expect("our entry");
        assert_eq!(key, our_key);
        assert_eq!(source.0, ours);
        assert_eq!(source.1.to_u32_vec(), our_path);

        // Only a foreign entry: nothing, even on a perfect path shape.
        let only_decoy = origins(&[(decoy_key, theirs, our_path)]);
        assert!(own_derivation(&only_decoy, ours).is_none());
        assert!(own_derivation(&TapKeyOrigins::new(), ours).is_none());
    }

    #[test]
    fn check_names_match_the_typescript_sdk() {
        let names: Vec<&str> = CheckName::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            [
                "inputs-own",
                "recipients-match",
                "change-own",
                "fee-budget",
                "opret-zero"
            ]
        );
        let kinds: Vec<&str> = [
            IntentKind::SendBtc,
            IntentKind::SendAsset,
            IntentKind::CreateUtxos,
        ]
        .iter()
        .map(|k| k.name())
        .collect();
        assert_eq!(kinds, ["send_btc", "send_asset", "create_utxos"]);
    }

    #[test]
    fn fail_all_lists_every_check_with_the_reason() {
        let verdict = fail_all("boom");
        assert!(!verdict.ok);
        assert_eq!(verdict.checks.len(), 5);
        assert_eq!(verdict.failed(), CheckName::ALL);
        assert!(verdict
            .checks
            .iter()
            .all(|c| !c.ok && c.detail.as_deref() == Some("boom")));
        assert_eq!(verdict.fee_sat, None);
        assert_eq!(verdict.txid, None);
        assert_eq!(
            verdict.first_failure().map(|c| c.check),
            Some(CheckName::InputsOwn)
        );
    }

    #[test]
    fn script_hex_from_address_requires_the_network() {
        let key = xonly(9);
        let script = bitcoin::ScriptBuf::new_p2tr(crate::secp(), key, None).to_hex_string();
        for network in BitcoinNetwork::ALL {
            let address = Address::p2tr(crate::secp(), key, None, network.to_bitcoin()).to_string();
            assert_eq!(
                script_hex_from_address(&address, network).as_deref(),
                Some(script.as_str()),
                "{network}"
            );
            // Mainnet and regtest addresses are foreign everywhere else;
            // testnet and signet share the `tb` prefix, as in bitcoin itself.
            let foreign = match network {
                BitcoinNetwork::Mainnet => BitcoinNetwork::Testnet,
                _ => BitcoinNetwork::Mainnet,
            };
            assert!(
                script_hex_from_address(&address, foreign).is_none(),
                "{network}"
            );
        }
        for bad in [
            "not-an-address",
            "",
            "bcrt1p",
            "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        ] {
            assert!(
                script_hex_from_address(bad, BitcoinNetwork::Regtest).is_none(),
                "{bad:?}"
            );
        }
    }
}
