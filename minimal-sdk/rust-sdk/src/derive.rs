//! Taproot re-derivation and origin-path matching.
//!
//! Re-derivation of taproot `tr(key)` scripts/addresses from account xpubs at
//! arbitrary keychain/index is the client-side half of change verification
//! (verify-before-sign check 3) and input-ownership proofs (check 1). It is
//! also how the app produces receive addresses without asking the gateway.
//!
//! Behavioural reference: `minimal-sdk/packages/client-sdk/src/derive.ts`.
//! Parity against rgb-lib's addresses is checked in `tests/parity.rs`.

use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::hex::DisplayHex;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::{Address, ScriptBuf};

use crate::keys::AccountXpubs;
use crate::network::{account_path_u32, BitcoinNetwork, HARDENED};
use crate::{secp, SdkError, SdkResult};

/// A taproot `tr(key)` output re-derived at `keychain/index` under one of the
/// two account xpubs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DerivedScript {
    pub keychain: u32,
    pub index: u32,
    /// BIP-341 tweaked output script (`OP_1 <32-byte key>`), lowercase hex.
    pub script_hex: String,
    /// Bech32m address for the network the xpub was derived on.
    pub address: String,
    /// Untweaked x-only internal key, 32 bytes lowercase hex.
    pub internal_key_hex: String,
}

/// Parse an account xpub string and check its version bytes belong to
/// `network` (xpub on mainnet, tpub everywhere else) — mirroring
/// `HDKey.fromExtendedKey(xpub, hdVersions(network))`, which rejects a key
/// serialized for a different network. Hardened derivation below an xpub is
/// impossible, so the account must already be `m/86'/coin'/0'`.
/// BIP-32 depth of an account key: `m / 86' / coin' / account'`.
const ACCOUNT_DEPTH: u8 = 3;

pub fn parse_account_xpub(xpub: &str, network: BitcoinNetwork) -> SdkResult<Xpub> {
    let parsed: Xpub = xpub.parse().map_err(|_| SdkError::InvalidInput {
        reason: "invalid account xpub: not a BIP-32 extended public key".into(),
    })?;
    if parsed.network != network.network_kind() {
        return Err(SdkError::InvalidInput {
            reason: format!("invalid account xpub: version bytes are not for {network}"),
        });
    }
    // Only an account-level key (`m/86'/coin'/account'`, depth 3, hardened
    // last step) makes `keychain/index` land where rgb-lib's addresses are.
    // A master or deeper key would derive silently wrong addresses.
    if parsed.depth != ACCOUNT_DEPTH || !parsed.child_number.is_hardened() {
        return Err(SdkError::InvalidInput {
            reason: format!(
                "invalid account xpub: expected an account-level key (depth {ACCOUNT_DEPTH}, hardened), got depth {}",
                parsed.depth
            ),
        });
    }
    Ok(parsed)
}

/// The two account xpubs as parsed keys, the form verify and
/// [`derive_for_origin_path`] consume. Public material only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAccounts {
    pub network: BitcoinNetwork,
    pub vanilla: Xpub,
    pub colored: Xpub,
}

impl ParsedAccounts {
    /// Parse the registration material returned by
    /// [`crate::keys::ClientKeys::xpubs`] (or received back from the gateway).
    pub fn parse(xpubs: &AccountXpubs) -> SdkResult<Self> {
        Ok(ParsedAccounts {
            network: xpubs.network,
            vanilla: parse_account_xpub(&xpubs.vanilla, xpubs.network)?,
            colored: parse_account_xpub(&xpubs.colored, xpubs.network)?,
        })
    }

    /// The account xpub for the colored (RGB) or vanilla (BTC) side.
    pub fn account(&self, colored: bool) -> &Xpub {
        if colored {
            &self.colored
        } else {
            &self.vanilla
        }
    }
}

/// Derive the taproot script/address at `keychain/index` under an account
/// xpub: derive the two unhardened children, take the x-only internal key,
/// build the BIP-341 `tr(key)` script (key-path only, no script tree) and its
/// bech32m address for `network`.
///
/// Errors only on a hardened `keychain`/`index` (impossible from an xpub).
/// It never panics: the values may come from attacker-controlled PSBT
/// metadata.
pub fn derive_taproot(
    account_xpub: &Xpub,
    keychain: u32,
    index: u32,
    network: BitcoinNetwork,
) -> SdkResult<DerivedScript> {
    let child = |what: &str, value: u32| {
        ChildNumber::from_normal_idx(value).map_err(|_| SdkError::DerivationFailed {
            reason: format!("{what} {value} is not an unhardened child index"),
        })
    };
    let children = [child("keychain", keychain)?, child("index", index)?];
    let key =
        account_xpub
            .derive_pub(secp(), &children)
            .map_err(|_| SdkError::DerivationFailed {
                reason: format!("public derivation at {keychain}/{index} failed"),
            })?;
    let internal_key: XOnlyPublicKey = key.public_key.into();
    let script = ScriptBuf::new_p2tr(secp(), internal_key, None);
    let address = Address::p2tr(secp(), internal_key, None, network.to_bitcoin());
    Ok(DerivedScript {
        keychain,
        index,
        script_hex: script.as_bytes().to_lower_hex_string(),
        address: address.to_string(),
        internal_key_hex: internal_key.serialize().to_lower_hex_string(),
    })
}

/// Which of the wallet's two accounts a key-origin path belongs to, and the
/// unhardened `keychain/index` under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginPathMatch {
    pub colored: bool,
    pub keychain: u32,
    pub index: u32,
}

/// Match a full master-based key-origin path (`[86', coin', 0', keychain,
/// index]`) against the user's two accounts.
///
/// **Single source of truth for path acceptance.** Verify proves scripts with
/// it (through [`derive_for_origin_path`]) and sign (via
/// [`crate::keys::ClientKeys::private_key_for_path`]) picks signing keys with
/// it. The two must never drift, or verify could approve a path that sign
/// will not use. Accepts exactly five children: the three hardened account
/// children of one of the two accounts for `network`, then an unhardened
/// keychain and an unhardened index. Returns `None` — never an error, never a
/// panic — on foreign paths: paths are attacker-controlled PSBT input.
pub fn match_origin_path(path: &[u32], network: BitcoinNetwork) -> Option<OriginPathMatch> {
    for colored in [false, true] {
        let prefix = account_path_u32(network, colored);
        if path.len() != prefix.len() + 2 {
            continue;
        }
        if path[..prefix.len()] != prefix {
            continue;
        }
        let keychain = path[prefix.len()];
        let index = path[prefix.len() + 1];
        if keychain >= HARDENED || index >= HARDENED {
            continue;
        }
        return Some(OriginPathMatch {
            colored,
            keychain,
            index,
        });
    }
    None
}

/// Re-derive the taproot script for a full master-based key-origin path
/// against the matching account xpub; `None` when the path is not ours or
/// the derivation fails. Never errors, never panics — the path is PSBT input.
pub fn derive_for_origin_path(
    path: &[u32],
    accounts: &ParsedAccounts,
    network: BitcoinNetwork,
) -> Option<DerivedScript> {
    let m = match_origin_path(path, network)?;
    derive_taproot(accounts.account(m.colored), m.keychain, m.index, network).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u32 = HARDENED;

    #[test]
    fn matches_both_accounts_only() {
        let net = BitcoinNetwork::Regtest;
        assert_eq!(
            match_origin_path(&[H + 86, H + 1, H, 0, 7], net),
            Some(OriginPathMatch {
                colored: false,
                keychain: 0,
                index: 7
            })
        );
        assert_eq!(
            match_origin_path(&[H + 86, H + 827_167, H, 1, 3], net),
            Some(OriginPathMatch {
                colored: true,
                keychain: 1,
                index: 3
            })
        );
        // Mainnet coin types are foreign on regtest and vice versa.
        assert_eq!(match_origin_path(&[H + 86, H, H, 0, 0], net), None);
        assert_eq!(
            match_origin_path(&[H + 86, H + 827_166, H, 0, 0], net),
            None
        );
        assert_eq!(
            match_origin_path(&[H + 86, H, H, 0, 0], BitcoinNetwork::Mainnet),
            Some(OriginPathMatch {
                colored: false,
                keychain: 0,
                index: 0
            })
        );
    }

    #[test]
    fn rejects_foreign_shapes_without_erroring() {
        let net = BitcoinNetwork::Regtest;
        let cases: &[&[u32]] = &[
            &[],
            &[H + 86],
            &[H + 86, H + 1, H],
            &[H + 86, H + 1, H, 0],
            &[H + 86, H + 1, H, 0, 0, 0],
            &[H + 84, H + 1, H, 0, 0],
            &[86, H + 1, H, 0, 0],
            &[H + 86, 1, H, 0, 0],
            &[H + 86, H + 1, 0, 0, 0],
            &[H + 86, H + 1, H + 1, 0, 0],
            &[H + 86, H + 1, H, H, 0],
            &[H + 86, H + 1, H, 0, H],
            &[H + 86, H + 1, H, u32::MAX, 0],
        ];
        for case in cases {
            assert_eq!(match_origin_path(case, net), None, "{case:?}");
        }
    }

    /// A deterministic account xpub for `kind`, from a fixed 32-byte seed.
    fn test_xpub(kind: bitcoin::NetworkKind) -> Xpub {
        let master = bitcoin::bip32::Xpriv::new_master(kind, &[7u8; 32]).unwrap();
        let account = master
            .derive_priv(
                secp(),
                &account_path_u32(BitcoinNetwork::Mainnet, false).map(ChildNumber::from),
            )
            .unwrap();
        Xpub::from_priv(secp(), &account)
    }

    #[test]
    fn derive_taproot_rejects_hardened_children_without_panicking() {
        let xpub = test_xpub(bitcoin::NetworkKind::Main);
        for (keychain, index) in [(HARDENED, 0), (0, HARDENED), (u32::MAX, u32::MAX)] {
            assert!(matches!(
                derive_taproot(&xpub, keychain, index, BitcoinNetwork::Mainnet),
                Err(SdkError::DerivationFailed { .. })
            ));
        }
        let ok = derive_taproot(&xpub, 0, 0, BitcoinNetwork::Mainnet).unwrap();
        assert!(ok.address.starts_with("bc1p"));
        assert_eq!(ok.script_hex.len(), 68);
        assert!(ok.script_hex.starts_with("5120"));
        assert_eq!(ok.script_hex, ok.script_hex.to_lowercase());
        assert_eq!(ok.internal_key_hex.len(), 64);
        // Deterministic.
        assert_eq!(
            derive_taproot(&xpub, 0, 0, BitcoinNetwork::Mainnet).unwrap(),
            ok
        );
        assert_ne!(
            derive_taproot(&xpub, 0, 1, BitcoinNetwork::Mainnet).unwrap(),
            ok
        );
    }

    #[test]
    fn parse_account_xpub_checks_version_bytes() {
        let mainnet = test_xpub(bitcoin::NetworkKind::Main).to_string();
        let testnet = test_xpub(bitcoin::NetworkKind::Test).to_string();
        assert!(mainnet.starts_with("xpub"));
        assert!(testnet.starts_with("tpub"));
        assert!(parse_account_xpub(&mainnet, BitcoinNetwork::Mainnet).is_ok());
        assert!(matches!(
            parse_account_xpub(&testnet, BitcoinNetwork::Mainnet),
            Err(SdkError::InvalidInput { .. })
        ));
        for net in [
            BitcoinNetwork::Testnet,
            BitcoinNetwork::Signet,
            BitcoinNetwork::Regtest,
        ] {
            assert!(parse_account_xpub(&testnet, net).is_ok(), "{net}");
            assert!(matches!(
                parse_account_xpub(&mainnet, net),
                Err(SdkError::InvalidInput { .. })
            ));
        }
        for bad in ["not-an-xpub", "", "xpub", &mainnet[..mainnet.len() - 1]] {
            let err = parse_account_xpub(bad, BitcoinNetwork::Mainnet).unwrap_err();
            assert!(matches!(err, SdkError::InvalidInput { .. }), "{bad:?}");
            // The error never echoes the caller's input.
            assert!(!err.to_string().contains(&mainnet[..20]));
        }
    }

    #[test]
    fn parse_account_xpub_rejects_keys_that_are_not_account_level() {
        let master =
            bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Main, &[7u8; 32]).unwrap();
        let account = master
            .derive_priv(
                secp(),
                &account_path_u32(BitcoinNetwork::Mainnet, false).map(ChildNumber::from),
            )
            .unwrap();
        let master_xpub = Xpub::from_priv(secp(), &master).to_string();
        let account_xpub = Xpub::from_priv(secp(), &account);
        let keychain_xpub = account_xpub
            .derive_pub(secp(), &[ChildNumber::from_normal_idx(0).unwrap()])
            .unwrap()
            .to_string();
        let unhardened_depth3 = Xpub::from_priv(
            secp(),
            &master
                .derive_priv(
                    secp(),
                    &[
                        ChildNumber::from_hardened_idx(86).unwrap(),
                        ChildNumber::from_hardened_idx(0).unwrap(),
                        ChildNumber::from_normal_idx(0).unwrap(),
                    ],
                )
                .unwrap(),
        )
        .to_string();
        assert!(parse_account_xpub(&account_xpub.to_string(), BitcoinNetwork::Mainnet).is_ok());
        for (what, bad) in [
            ("master (depth 0)", master_xpub),
            ("keychain (depth 4)", keychain_xpub),
            ("unhardened depth 3", unhardened_depth3),
        ] {
            let err = parse_account_xpub(&bad, BitcoinNetwork::Mainnet).unwrap_err();
            assert!(
                matches!(&err, SdkError::InvalidInput { reason } if reason.contains("account-level")),
                "{what}: {err:?}"
            );
        }
    }
}
