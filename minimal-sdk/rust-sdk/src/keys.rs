//! Key generation and restore, mirroring rgb-lib's derivation exactly
//! (cross-checked against the rgb-lib-generated fixture in
//! `minimal-sdk/packages/client-sdk/test/fixtures/rgblib-parity.json`):
//! BIP-39 seed (empty passphrase) → master → account xprv/xpub at
//! `m/86'/coin'/0'` for the vanilla and colored keychains.
//!
//! The mnemonic is the user's ONLY backup and never leaves the client; only
//! xpubs and the master fingerprint are shared with the gateway (design doc
//! I1/I2). Behavioural reference: `minimal-sdk/packages/client-sdk/src/keys.ts`.
//!
//! Secrets hygiene, enforced here and asserted in `tests/parity.rs`:
//! - [`ClientKeys`] holds the two account xprvs and nothing else: the mnemonic,
//!   the seed and the master xprv are wiped and dropped at the end of
//!   construction and are not retrievable through any method; the account
//!   xprvs are wiped again when the `ClientKeys` is dropped, so key material
//!   does not linger in freed memory of a long-lived mobile process;
//! - [`ClientKeys`] has a **manual** `Debug` impl that renders only public
//!   material; the same goes for [`GeneratedKeys`];
//! - no error path formats the words supplied: a bad mnemonic is
//!   [`SdkError::InvalidMnemonic`] with no payload.

use std::fmt;
use std::sync::Arc;

use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, Fingerprint, Xpriv, Xpub};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::SecretKey;

use crate::derive::{match_origin_path, ParsedAccounts};
use crate::network::{account_path, BitcoinNetwork};
use crate::{secp, SdkError, SdkResult};

/// Word count of a freshly generated mnemonic (128 bits of entropy).
const GENERATED_WORD_COUNT: usize = 12;

/// Public account material — safe to share, used to register with the gateway.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountXpubs {
    pub network: BitcoinNetwork,
    /// Master key fingerprint, 8 lowercase hex chars.
    pub fingerprint: String,
    /// Account xpub for the vanilla (BTC) keychain, `m/86'/coin'/0'`.
    pub vanilla: String,
    /// Account xpub for the colored (RGB) keychain, `m/86'/rgb-coin'/0'`.
    pub colored: String,
}

/// Result of [`ClientKeys::generate`]: the mnemonic the user must back up,
/// and the keys derived from it. This is the **only** place the mnemonic is
/// ever handed back, and only because the caller has to show it once.
#[derive(uniffi::Record)]
pub struct GeneratedKeys {
    pub mnemonic: String,
    pub keys: Arc<ClientKeys>,
}

impl fmt::Debug for GeneratedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedKeys")
            .field("mnemonic", &"[redacted]")
            .field("keys", &self.keys)
            .finish()
    }
}

/// Client-side key material. Holds the account xprvs needed for signing.
#[derive(uniffi::Object)]
pub struct ClientKeys {
    network: BitcoinNetwork,
    fingerprint: Fingerprint,
    vanilla_account: Xpriv,
    colored_account: Xpriv,
}

/// Renders no secret: network, fingerprint and the two account **xpubs**.
impl fmt::Debug for ClientKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientKeys")
            .field("network", &self.network)
            .field("fingerprint", &self.fingerprint_hex())
            .field("vanilla_xpub", &self.vanilla_xpub().to_string())
            .field("colored_xpub", &self.colored_xpub().to_string())
            .finish()
    }
}

impl ClientKeys {
    /// Generate a fresh 12-word mnemonic and derive keys from it.
    pub fn generate(network: BitcoinNetwork) -> SdkResult<GeneratedKeys> {
        let mnemonic =
            Mnemonic::generate(GENERATED_WORD_COUNT).map_err(|_| SdkError::Internal {
                reason: "mnemonic generation failed".into(),
            })?;
        let keys = Self::from_parsed(&mnemonic, network)?;
        Ok(GeneratedKeys {
            mnemonic: mnemonic.to_string(),
            keys: Arc::new(keys),
        })
    }

    /// Restore keys from an existing mnemonic; `InvalidMnemonic` on a bad
    /// word, word count or checksum. The error deliberately carries nothing
    /// about the words supplied.
    pub fn from_mnemonic(mnemonic: &str, network: BitcoinNetwork) -> SdkResult<ClientKeys> {
        let parsed = Mnemonic::parse(mnemonic).map_err(|_| SdkError::InvalidMnemonic)?;
        Self::from_parsed(&parsed, network)
    }

    fn from_parsed(mnemonic: &Mnemonic, network: BitcoinNetwork) -> SdkResult<ClientKeys> {
        // Empty passphrase, exactly as rgb-lib derives.
        let mut seed = mnemonic.to_seed("");
        let result = Self::from_seed(&seed, network);
        // Wipe the seed whether or not derivation succeeded; `master` is
        // wiped inside `from_seed`. Only the two account xprvs survive.
        wipe(&mut seed);
        result
    }

    fn from_seed(seed: &[u8; 64], network: BitcoinNetwork) -> SdkResult<ClientKeys> {
        let mut master = Xpriv::new_master(network.network_kind(), seed).map_err(|_| {
            SdkError::DerivationFailed {
                reason: "master key".into(),
            }
        })?;
        let derive = |colored: bool| {
            master
                .derive_priv(secp(), &account_path(network, colored))
                .map_err(|_| SdkError::DerivationFailed {
                    reason: format!("account (colored={colored})"),
                })
        };
        let keys = ClientKeys {
            network,
            fingerprint: master.fingerprint(secp()),
            vanilla_account: derive(false)?,
            colored_account: derive(true)?,
        };
        master.private_key.non_secure_erase();
        Ok(keys)
    }

    /// Master key fingerprint as raw bytes (PSBT key-origin comparison).
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Account xpub for the vanilla (BTC) keychain.
    pub fn vanilla_xpub(&self) -> Xpub {
        Xpub::from_priv(secp(), &self.vanilla_account)
    }

    /// Account xpub for the colored (RGB) keychain.
    pub fn colored_xpub(&self) -> Xpub {
        Xpub::from_priv(secp(), &self.colored_account)
    }

    /// The two account xpubs as parsed keys, ready for
    /// [`crate::derive::derive_for_origin_path`]. Public material only.
    pub fn accounts(&self) -> ParsedAccounts {
        ParsedAccounts {
            network: self.network,
            vanilla: self.vanilla_xpub(),
            colored: self.colored_xpub(),
        }
    }

    /// Private key for a full master-based path `[86', coin', 0', keychain,
    /// index]` as found in PSBT key-origin metadata; `None` when the path is
    /// not one of this wallet's two accounts (never errors, never panics —
    /// used on adversarial input).
    pub fn private_key_for_path(&self, path: &[u32]) -> Option<SecretKey> {
        // Path acceptance is delegated to `match_origin_path`, the single
        // source of truth shared with verify (`derive_for_origin_path`).
        // There is deliberately no second path check here: what verify
        // proved is exactly what sign derives, and the private key returned
        // for an accepted path is the key whose x-only public key verify
        // re-derived as the input's internal key (asserted in tests/parity.rs).
        let m = match_origin_path(path, self.network)?;
        let account = if m.colored {
            &self.colored_account
        } else {
            &self.vanilla_account
        };
        let children = [
            ChildNumber::from_normal_idx(m.keychain).ok()?,
            ChildNumber::from_normal_idx(m.index).ok()?,
        ];
        Some(account.derive_priv(secp(), &children).ok()?.private_key)
    }
}

/// The uniffi surface of [`ClientKeys`]. Only public material crosses the
/// boundary: no method returns a mnemonic, seed, xprv or private key.
#[uniffi::export]
impl ClientKeys {
    /// Restore keys from an existing mnemonic (`InvalidMnemonic` on a bad
    /// checksum, word or word count).
    #[uniffi::constructor(name = "from_mnemonic")]
    pub fn ffi_from_mnemonic(mnemonic: String, network: BitcoinNetwork) -> SdkResult<Arc<Self>> {
        Ok(Arc::new(Self::from_mnemonic(&mnemonic, network)?))
    }

    /// Network these keys were derived for.
    pub fn network(&self) -> BitcoinNetwork {
        self.network
    }

    /// Master key fingerprint, 8 lowercase hex chars.
    #[uniffi::method(name = "fingerprint")]
    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint.as_bytes().to_lower_hex_string()
    }

    /// Public registration material; never contains private keys.
    pub fn xpubs(&self) -> AccountXpubs {
        AccountXpubs {
            network: self.network,
            fingerprint: self.fingerprint_hex(),
            vanilla: self.vanilla_xpub().to_string(),
            colored: self.colored_xpub().to_string(),
        }
    }
}

/// Wipe the account private keys when the keys go away. `non_secure_erase`
/// is secp256k1's best-effort overwrite (volatile writes the optimiser cannot
/// elide); it is not a guarantee against every copy the allocator made. The
/// chain codes are left: with the private key gone they only reproduce the
/// public xpub, which is shared with the gateway anyway.
impl Drop for ClientKeys {
    fn drop(&mut self) {
        self.vanilla_account.private_key.non_secure_erase();
        self.colored_account.private_key.non_secure_erase();
    }
}

/// Overwrite a secret buffer with zeros through volatile writes so the
/// store is not optimised away as dead.
fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference for the write.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
