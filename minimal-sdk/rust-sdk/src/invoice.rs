//! Invoice decoding for intent construction:
//!
//! - **BOLT-11** (payee, amount, payment hash, payment secret, description,
//!   expiry): a minimal decoder over the `bech32` crate `bitcoin` already
//!   re-exports, plus secp256k1 signature recovery for the payee.
//! - **RGB invoices** in the rgb-invoicing v0.11 grammar
//!   `rgb:<contract|~>/<schema|~>/<state|~>/<beneficiary>?expiry=&endpoints=`
//!   (asset id, amount, beneficiary kind, transports). A witness beneficiary is
//!   a `wvout:` recipient id, not a plain address. Full RGB validation is
//!   explicitly out of scope (design doc): this parses the grammar, it does not
//!   validate the contract.
//!
//! Both decoders are fed **user-pasted strings**. Every malformed input is
//! [`SdkError::InvoiceDecode`] and nothing else; no path can panic (asserted
//! in `tests/parity.rs` by truncating and corrupting real invoices at every
//! position).
//!
//! Behavioural reference: `minimal-sdk/packages/client-sdk/src/invoice.ts`.
//!
//! **Why the bech32 checksum is run by hand.** The `bech32` crate's checked
//! decoder enforces the BIP-173 code length (1023 characters), but BOLT-11
//! explicitly lifts that limit — invoices carrying route hints routinely
//! exceed it. The TypeScript reference decodes with the length limit disabled;
//! this port uses the crate's character/HRP validation and its checksum engine
//! directly, which validates the same polynomial without the length cap.

use bitcoin::bech32::primitives::checksum::{Checksum, Engine};
use bitcoin::bech32::primitives::decode::UncheckedHrpstring;
use bitcoin::bech32::{Bech32, Fe32};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use bitcoin::secp256k1::{Message, PublicKey};

use crate::network::BitcoinNetwork;
use crate::{secp, SdkError, SdkResult};

fn invalid(reason: impl Into<String>) -> SdkError {
    SdkError::InvoiceDecode {
        reason: reason.into(),
    }
}

// ---------------------------------------------------------------------------
// BOLT-11
// ---------------------------------------------------------------------------

/// A decoded BOLT-11 invoice: the fields intent construction needs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Bolt11Invoice {
    pub network: BitcoinNetwork,
    /// Invoice amount in millisatoshi; `None` for any-amount invoices.
    pub amount_msat: Option<u64>,
    /// 32-byte payment hash, lowercase hex.
    pub payment_hash: String,
    /// 32-byte payment secret, lowercase hex (`None` on legacy invoices).
    pub payment_secret: Option<String>,
    /// Short description, or `None` when only a description hash is present.
    pub description: Option<String>,
    pub description_hash: Option<String>,
    /// Payee node id (33-byte compressed pubkey, lowercase hex), recovered
    /// from the signature or taken from the `n` tag after verifying the
    /// signature against it.
    pub payee_node_id: String,
    /// Invoice creation time, unix seconds.
    pub timestamp: u64,
    /// Seconds until expiry (BOLT-11 default 3600).
    pub expiry_seconds: u64,
}

/// HRP network prefixes, longest-prefix-first where one is a prefix of another
/// (`bcrt` before `bc`, `tbs` before `tb`).
const HRP_NETWORKS: [(&str, BitcoinNetwork); 4] = [
    ("bcrt", BitcoinNetwork::Regtest),
    ("tbs", BitcoinNetwork::Signet),
    ("bc", BitcoinNetwork::Mainnet),
    ("tb", BitcoinNetwork::Testnet),
];

const MSAT_PER_BTC: u64 = 100_000_000_000;

/// BOLT-11 tagged-field types this decoder reads.
const TAG_PAYMENT_HASH: u8 = 1; // p
const TAG_EXPIRY: u8 = 6; // x
const TAG_DESCRIPTION: u8 = 13; // d
const TAG_PAYMENT_SECRET: u8 = 16; // s
const TAG_PAYEE: u8 = 19; // n
const TAG_DESCRIPTION_HASH: u8 = 23; // h

/// Words in a 65-byte recoverable signature (65 * 8 / 5).
const SIGNATURE_WORDS: usize = 104;
/// Words in the 35-bit timestamp.
const TIMESTAMP_WORDS: usize = 7;

fn parse_hrp(hrp: &str) -> SdkResult<(BitcoinNetwork, Option<u64>)> {
    let rest = hrp
        .strip_prefix("ln")
        .ok_or_else(|| invalid(format!("not a BOLT11 HRP: {hrp}")))?;
    let (prefix, network) = HRP_NETWORKS
        .iter()
        .find(|(prefix, _)| rest.starts_with(prefix))
        .copied()
        .ok_or_else(|| invalid(format!("unknown network prefix: {rest}")))?;
    let amount_part = &rest[prefix.len()..];
    if amount_part.is_empty() {
        return Ok((network, None));
    }
    // `^(\d+)([munp])?$`
    let (digits, unit) = match amount_part.as_bytes().last() {
        Some(b'm' | b'u' | b'n' | b'p') => {
            let (d, u) = amount_part.split_at(amount_part.len() - 1);
            (d, Some(u))
        }
        _ => (amount_part, None),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!("malformed amount: {amount_part}")));
    }
    let value: u64 = digits
        .parse()
        .map_err(|_| invalid(format!("amount out of range: {amount_part}")))?;
    let msat = match unit {
        None => value.checked_mul(MSAT_PER_BTC),
        Some("m") => value.checked_mul(MSAT_PER_BTC / 1_000),
        Some("u") => value.checked_mul(MSAT_PER_BTC / 1_000_000),
        Some("n") => value.checked_mul(MSAT_PER_BTC / 1_000_000_000),
        Some("p") => {
            if !value.is_multiple_of(10) {
                return Err(invalid("sub-millisatoshi pico amount"));
            }
            Some(value / 10)
        }
        Some(_) => return Err(invalid(format!("malformed amount: {amount_part}"))),
    };
    let msat = msat.ok_or_else(|| invalid(format!("amount out of range: {amount_part}")))?;
    Ok((network, Some(msat)))
}

/// Pack 5-bit words into bytes MSB-first, zero-padding the tail (BIP-173).
fn words_to_bytes_padded(words: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 5 / 8 + 1);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &word in words {
        acc = (acc << 5) | u32::from(word & 0x1f);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            bytes.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 {
        bytes.push(((acc << (8 - bits)) & 0xff) as u8);
    }
    bytes
}

/// Pack 5-bit words into bytes, DROPPING trailing pad bits (tagged fields).
fn words_to_bytes_trimmed(words: &[u8]) -> Vec<u8> {
    let mut bytes = words_to_bytes_padded(words);
    bytes.truncate(words.len() * 5 / 8);
    bytes
}

/// Big-endian base-32 integer; `None` on overflow (a hostile tag length).
fn words_to_u64(words: &[u8]) -> Option<u64> {
    words.iter().try_fold(0u64, |acc, &w| {
        acc.checked_mul(32)?.checked_add(u64::from(w & 0x1f))
    })
}

/// Bech32 decode with the code-length limit disabled: character, case, HRP
/// and separator validation from the `bech32` crate, checksum from its
/// engine. Returns the lowercase HRP and the 5-bit data words without the
/// checksum.
fn bech32_decode_unlimited(invoice: &str) -> SdkResult<(String, Vec<u8>)> {
    let lower = invoice.to_lowercase();
    let unchecked = UncheckedHrpstring::new(&lower)
        .map_err(|e| invalid(format!("bech32 decode failed: {e}")))?;
    let hrp = unchecked.hrp();
    let ascii = unchecked.data_part_ascii();
    if ascii.len() < Bech32::CHECKSUM_LENGTH {
        return Err(invalid(
            "bech32 decode failed: data part shorter than checksum",
        ));
    }
    let mut engine = Engine::<Bech32>::new();
    engine.input_hrp(hrp);
    // Characters were validated by `UncheckedHrpstring::new`.
    let words: Vec<u8> = ascii
        .iter()
        .map(|&b| Fe32::from_char_unchecked(b))
        .inspect(|fe| engine.input_fe(*fe))
        .map(Fe32::to_u8)
        .collect();
    if *engine.residue() != Bech32::TARGET_RESIDUE {
        return Err(invalid("bech32 decode failed: invalid checksum"));
    }
    let data_len = words.len() - Bech32::CHECKSUM_LENGTH;
    let mut words = words;
    words.truncate(data_len);
    Ok((hrp.to_lowercase(), words))
}

/// Decode a BOLT-11 invoice. Malformed input — wrong checksum, truncated
/// data, unknown HRP, bad tag lengths, an unrecoverable signature — is
/// `InvoiceDecode`; nothing here panics on hostile input.
pub fn decode_bolt11(invoice: &str) -> SdkResult<Bolt11Invoice> {
    let (hrp, words) = bech32_decode_unlimited(invoice)?;
    let (network, amount_msat) = parse_hrp(&hrp)?;
    if words.len() < SIGNATURE_WORDS + TIMESTAMP_WORDS {
        return Err(invalid("data part too short"));
    }
    let (data_words, signature_words) = words.split_at(words.len() - SIGNATURE_WORDS);
    let timestamp = words_to_u64(&data_words[..TIMESTAMP_WORDS])
        .ok_or_else(|| invalid("timestamp out of range"))?;

    let mut payment_hash: Option<String> = None;
    let mut payment_secret: Option<String> = None;
    let mut description: Option<String> = None;
    let mut description_hash: Option<String> = None;
    let mut payee_from_tag: Option<Vec<u8>> = None;
    let mut expiry_seconds: u64 = 3600;

    let mut cursor = TIMESTAMP_WORDS;
    while cursor < data_words.len() {
        let tag_type = data_words[cursor];
        let (high, low) = match (data_words.get(cursor + 1), data_words.get(cursor + 2)) {
            (Some(h), Some(l)) => (*h, *l),
            _ => return Err(invalid("truncated tag")),
        };
        let length = usize::from(high) * 32 + usize::from(low);
        let start = cursor + 3;
        let data = data_words
            .get(start..start + length)
            .ok_or_else(|| invalid("truncated tag data"))?;
        cursor = start + length;
        match tag_type {
            TAG_PAYMENT_HASH => {
                if length == 52 && payment_hash.is_none() {
                    payment_hash = Some(words_to_bytes_trimmed(data).to_lower_hex_string());
                }
            }
            TAG_PAYMENT_SECRET => {
                if length == 52 && payment_secret.is_none() {
                    payment_secret = Some(words_to_bytes_trimmed(data).to_lower_hex_string());
                }
            }
            TAG_DESCRIPTION => {
                description =
                    Some(String::from_utf8_lossy(&words_to_bytes_trimmed(data)).into_owned());
            }
            TAG_DESCRIPTION_HASH => {
                if length == 52 {
                    description_hash = Some(words_to_bytes_trimmed(data).to_lower_hex_string());
                }
            }
            TAG_PAYEE => {
                if length == 53 {
                    payee_from_tag = Some(words_to_bytes_trimmed(data));
                }
            }
            TAG_EXPIRY => {
                expiry_seconds =
                    words_to_u64(data).ok_or_else(|| invalid("expiry out of range"))?;
            }
            // Features, route hints, fallback address, min-final-cltv, metadata:
            // not needed for intent construction.
            _ => {}
        }
    }
    let payment_hash = payment_hash.ok_or_else(|| invalid("missing payment hash"))?;

    let signature = words_to_bytes_trimmed(signature_words);
    if signature.len() != 65 {
        return Err(invalid("malformed signature"));
    }
    let recovery_id = signature[64];
    if recovery_id > 3 {
        return Err(invalid(format!("invalid recovery id {recovery_id}")));
    }
    // BOLT-11: the signature commits to sha256(hrp || data-part bytes), the
    // data part packed MSB-first with zero padding.
    let mut message = hrp.clone().into_bytes();
    message.extend_from_slice(&words_to_bytes_padded(data_words));
    let digest = Message::from_digest(sha256::Hash::hash(&message).to_byte_array());

    let payee_node_id = match payee_from_tag {
        Some(payee_bytes) => {
            let payee = PublicKey::from_slice(&payee_bytes)
                .map_err(|_| invalid("malformed payee node id"))?;
            let sig = Signature::from_compact(&signature[..64])
                .map_err(|_| invalid("signature recovery failed: malformed signature"))?;
            secp()
                .verify_ecdsa(&digest, &sig, &payee)
                .map_err(|_| invalid("signature does not match payee node id"))?;
            payee.serialize().to_lower_hex_string()
        }
        None => {
            let recid = RecoveryId::from_i32(i32::from(recovery_id))
                .map_err(|_| invalid(format!("invalid recovery id {recovery_id}")))?;
            let sig = RecoverableSignature::from_compact(&signature[..64], recid)
                .map_err(|_| invalid("signature recovery failed: malformed signature"))?;
            let recovered = secp()
                .recover_ecdsa(&digest, &sig)
                .map_err(|_| invalid("signature recovery failed"))?;
            recovered.serialize().to_lower_hex_string()
        }
    };

    Ok(Bolt11Invoice {
        network,
        amount_msat,
        payment_hash,
        payment_secret,
        description,
        description_hash,
        payee_node_id,
        timestamp,
        expiry_seconds,
    })
}

// ---------------------------------------------------------------------------
// RGB invoices
// ---------------------------------------------------------------------------

/// How the RGB beneficiary is paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BeneficiaryKind {
    /// `utxob:` — a blinded seal on an existing UTXO of the receiver.
    Blind,
    /// `wvout:` — paid by a new output of the sender's witness transaction.
    Witness,
    /// Neither grammar matched; the recipient id is passed through untouched.
    Unknown,
}

/// A decoded RGB invoice (rgb-invoicing v0.11 grammar).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RgbInvoice {
    /// Full asset id (`rgb:…`), or `None` for asset-agnostic invoices.
    pub asset_id: Option<String>,
    /// Schema id segment, or `None` when omitted.
    pub schema: Option<String>,
    /// Fungible amount, or `None` (omitted / non-fungible state).
    pub amount: Option<u64>,
    /// Raw assignment-state segment when present and non-numeric.
    pub assignment_raw: Option<String>,
    /// Chain-qualified beneficiary — exactly the `recipient_id` the gateway's
    /// send-asset prepare expects (e.g. `bcrt:utxob:…` or `bcrt:wvout:…`).
    pub recipient_id: String,
    pub beneficiary_kind: BeneficiaryKind,
    /// Chain prefix of the beneficiary (`bc`, `tb`, `bcrt`, …).
    pub chain: Option<String>,
    /// Consignment transport endpoints from the `endpoints` query param.
    pub transport_endpoints: Vec<String>,
    /// Unix-seconds expiry from the `expiry` query param.
    pub expiry_timestamp: Option<u64>,
    pub assignment_name: Option<String>,
}

/// The rgb-invoicing placeholder for an omitted path segment.
const OMITTED: &str = "~";

/// `decodeURIComponent` semantics: `%XX` sequences become bytes and the
/// result must be valid UTF-8; otherwise the value is returned unchanged.
/// `+` is **not** a space.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = match bytes.get(i + 1..i + 3) {
                Some(h) => h,
                None => return value.to_owned(),
            };
            // `from_str_radix` would accept a sign (`%+4`); decodeURIComponent
            // does not, so require two hex digits explicitly.
            let decoded = match std::str::from_utf8(hex)
                .ok()
                .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                Some(b) => b,
                None => return value.to_owned(),
            };
            out.push(decoded);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| value.to_owned())
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `^([a-z0-9]+):(utxob|wvout):(.+)$`
fn parse_beneficiary(seg: &str) -> Option<(String, BeneficiaryKind)> {
    let (chain, rest) = seg.split_once(':')?;
    if chain.is_empty()
        || !chain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    let (kind, id) = rest.split_once(':')?;
    let kind = match kind {
        "utxob" => BeneficiaryKind::Blind,
        "wvout" => BeneficiaryKind::Witness,
        _ => return None,
    };
    if id.is_empty() {
        return None;
    }
    Some((chain.to_owned(), kind))
}

/// Decode an RGB invoice. The `~` placeholder marks an omitted contract,
/// schema or state segment. Malformed input is `InvoiceDecode`.
pub fn decode_rgb_invoice(invoice: &str) -> SdkResult<RgbInvoice> {
    let body = invoice
        .strip_prefix("rgb:")
        .ok_or_else(|| invalid("missing rgb: scheme"))?;
    let (path, query) = match body.split_once('?') {
        Some((p, q)) => (p, q),
        None => (body, ""),
    };

    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() != 4 {
        return Err(invalid(format!(
            "expected contract/schema/state/beneficiary, got {} segment(s)",
            segments.len()
        )));
    }
    let (contract_seg, schema_seg, state_seg, beneficiary_seg) =
        (segments[0], segments[1], segments[2], segments[3]);
    if beneficiary_seg.is_empty() {
        return Err(invalid("empty beneficiary"));
    }

    let asset_id = (contract_seg != OMITTED).then(|| format!("rgb:{contract_seg}"));
    let schema = (schema_seg != OMITTED).then(|| schema_seg.to_owned());
    let mut amount: Option<u64> = None;
    let mut assignment_raw: Option<String> = None;
    if state_seg != OMITTED {
        if is_all_digits(state_seg) {
            amount = Some(
                state_seg
                    .parse()
                    .map_err(|_| invalid(format!("amount out of range: {state_seg}")))?,
            );
        } else {
            assignment_raw = Some(state_seg.to_owned());
        }
    }

    let (chain, beneficiary_kind) = match parse_beneficiary(beneficiary_seg) {
        Some((chain, kind)) => (Some(chain), kind),
        None => (None, BeneficiaryKind::Unknown),
    };

    let mut transport_endpoints: Vec<String> = Vec::new();
    let mut expiry_timestamp: Option<u64> = None;
    let mut assignment_name: Option<String> = None;
    if !query.is_empty() {
        for pair in query.split('&') {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| invalid(format!("malformed query parameter: {pair}")))?;
            let key = percent_decode(key);
            let value = percent_decode(value);
            match key.as_str() {
                "endpoints" => {
                    transport_endpoints = value
                        .split(',')
                        .filter(|endpoint| !endpoint.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                "expiry" => {
                    if !is_all_digits(&value) {
                        return Err(invalid(format!("invalid expiry: {value}")));
                    }
                    expiry_timestamp = Some(
                        value
                            .parse()
                            .map_err(|_| invalid(format!("invalid expiry: {value}")))?,
                    );
                }
                "assignment_name" => assignment_name = Some(value),
                _ => {}
            }
        }
    }

    Ok(RgbInvoice {
        asset_id,
        schema,
        amount,
        assignment_raw,
        recipient_id: beneficiary_seg.to_owned(),
        beneficiary_kind,
        chain,
        transport_endpoints,
        expiry_timestamp,
        assignment_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hrp_amounts_follow_bolt11_multipliers() {
        assert_eq!(parse_hrp("lnbc").unwrap(), (BitcoinNetwork::Mainnet, None));
        assert_eq!(
            parse_hrp("lnbc1").unwrap(),
            (BitcoinNetwork::Mainnet, Some(MSAT_PER_BTC))
        );
        assert_eq!(
            parse_hrp("lnbc2500u").unwrap(),
            (BitcoinNetwork::Mainnet, Some(250_000_000))
        );
        assert_eq!(
            parse_hrp("lntb20m").unwrap(),
            (BitcoinNetwork::Testnet, Some(2_000_000_000))
        );
        assert_eq!(
            parse_hrp("lnbcrt10n").unwrap(),
            (BitcoinNetwork::Regtest, Some(1_000))
        );
        assert_eq!(
            parse_hrp("lntbs250p").unwrap(),
            (BitcoinNetwork::Signet, Some(25))
        );
        for bad in [
            "bc",
            "lnxx1",
            "lnbc25a",
            "lnbcm",
            "lnbc251p",
            "lnbc999999999999999999999",
        ] {
            assert!(
                matches!(parse_hrp(bad), Err(SdkError::InvoiceDecode { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn word_packing_matches_bip173() {
        // 8 words = 40 bits = 5 bytes exactly.
        assert_eq!(
            words_to_bytes_padded(&[31, 31, 31, 31, 31, 31, 31, 31]),
            vec![0xff; 5]
        );
        // 7 words = 35 bits: padded gives 5 bytes, trimmed gives 4.
        assert_eq!(words_to_bytes_padded(&[0; 7]).len(), 5);
        assert_eq!(words_to_bytes_trimmed(&[0; 7]).len(), 4);
        assert_eq!(words_to_u64(&[1, 0]), Some(32));
        assert_eq!(words_to_u64(&[31; 13]), None);
    }

    #[test]
    fn percent_decode_matches_decode_uri_component() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("rpc%3A%2F%2Fx"), "rpc://x");
        assert_eq!(percent_decode("a+b"), "a+b");
        // Malformed escapes are returned unchanged, never an error.
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
        assert_eq!(percent_decode("trail%2"), "trail%2");
        assert_eq!(percent_decode("%ff"), "%ff");
        // A sign is not a hex digit (u8::from_str_radix would accept it).
        assert_eq!(percent_decode("%+4"), "%+4");
        assert_eq!(percent_decode("a%+41"), "a%+41");
    }

    #[test]
    fn beneficiary_grammar() {
        assert_eq!(
            parse_beneficiary("bcrt:wvout:abc"),
            Some(("bcrt".into(), BeneficiaryKind::Witness))
        );
        assert_eq!(
            parse_beneficiary("bc:utxob:abc"),
            Some(("bc".into(), BeneficiaryKind::Blind))
        );
        for bad in [
            "bcrt:other:abc",
            "BC:utxob:abc",
            ":utxob:abc",
            "bc:utxob:",
            "bc1q...",
        ] {
            assert_eq!(parse_beneficiary(bad), None, "{bad}");
        }
    }
}
