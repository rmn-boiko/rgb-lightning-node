//! Network constants mirroring rgb-lib exactly (rgb-lib `src/utils.rs`,
//! `get_coin_type`): BIP-86 purpose, account 0, keychain 0 on both the vanilla
//! (standard coin type) and colored (RGB coin type 827166/827167) sides.
//!
//! Behavioural reference: `minimal-sdk/packages/client-sdk/src/network.ts`.

use std::fmt;

use bitcoin::bip32::ChildNumber;
use bitcoin::{Network, NetworkKind};

/// BIP-86 purpose (`86'`).
pub const PURPOSE: u32 = 86;
/// Account index (`0'`) for both the vanilla and the colored account.
pub const ACCOUNT: u32 = 0;
/// External keychain (`0`) — the only keychain own *outputs* may use.
pub const KEYCHAIN: u32 = 0;
/// BIP-32 hardened-index threshold.
pub const HARDENED: u32 = 0x8000_0000;

/// RGB coin type on mainnet (rgb-lib `get_coin_type`).
pub const COIN_RGB_MAINNET: u32 = 827_166;
/// RGB coin type on every non-mainnet network.
pub const COIN_RGB_TESTNET: u32 = 827_167;

/// BIP-44 coin type for vanilla (BTC) keys on mainnet.
pub const COIN_BTC_MAINNET: u32 = 0;
/// BIP-44 coin type for vanilla (BTC) keys on every non-mainnet network.
pub const COIN_BTC_TESTNET: u32 = 1;

/// The four networks the gateway and rgb-lib know about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

/// Version bytes for extended key serialization (xprv/xpub vs tprv/tpub).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdVersions {
    pub private: u32,
    pub public: u32,
}

const MAINNET_VERSIONS: HdVersions = HdVersions {
    private: 0x0488_ade4,
    public: 0x0488_b21e,
};
const TESTNET_VERSIONS: HdVersions = HdVersions {
    private: 0x0435_8394,
    public: 0x0435_87cf,
};

impl BitcoinNetwork {
    /// All networks, in the order the parity fixture lists them.
    pub const ALL: [BitcoinNetwork; 4] = [
        BitcoinNetwork::Mainnet,
        BitcoinNetwork::Testnet,
        BitcoinNetwork::Signet,
        BitcoinNetwork::Regtest,
    ];

    /// Canonical name as used by the gateway API and the parity fixture.
    pub fn name(self) -> &'static str {
        match self {
            BitcoinNetwork::Mainnet => "Mainnet",
            BitcoinNetwork::Testnet => "Testnet",
            BitcoinNetwork::Signet => "Signet",
            BitcoinNetwork::Regtest => "Regtest",
        }
    }

    /// The `bitcoin` crate network (address encoding, script rules).
    pub fn to_bitcoin(self) -> Network {
        match self {
            BitcoinNetwork::Mainnet => Network::Bitcoin,
            BitcoinNetwork::Testnet => Network::Testnet,
            BitcoinNetwork::Signet => Network::Signet,
            BitcoinNetwork::Regtest => Network::Regtest,
        }
    }

    /// Main vs Test: selects the xprv/xpub or tprv/tpub serialization.
    pub fn network_kind(self) -> NetworkKind {
        match self {
            BitcoinNetwork::Mainnet => NetworkKind::Main,
            _ => NetworkKind::Test,
        }
    }

    /// Extended-key version bytes for this network.
    pub fn hd_versions(self) -> HdVersions {
        match self {
            BitcoinNetwork::Mainnet => MAINNET_VERSIONS,
            _ => TESTNET_VERSIONS,
        }
    }

    /// Bech32 human-readable part for addresses: `bc` / `tb` / `tb` / `bcrt`.
    pub fn bech32_hrp(self) -> &'static str {
        match self {
            BitcoinNetwork::Mainnet => "bc",
            BitcoinNetwork::Testnet | BitcoinNetwork::Signet => "tb",
            BitcoinNetwork::Regtest => "bcrt",
        }
    }

    /// Whether this is mainnet (real funds).
    pub fn is_mainnet(self) -> bool {
        self == BitcoinNetwork::Mainnet
    }
}

impl fmt::Display for BitcoinNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// BIP-44 coin type: the standard BTC coin type for vanilla keys, the RGB
/// coin type for colored keys.
pub fn coin_type(network: BitcoinNetwork, colored: bool) -> u32 {
    match (colored, network.is_mainnet()) {
        (true, true) => COIN_RGB_MAINNET,
        (true, false) => COIN_RGB_TESTNET,
        (false, true) => COIN_BTC_MAINNET,
        (false, false) => COIN_BTC_TESTNET,
    }
}

/// Hardened account derivation path children: `[86', coin', 0']`.
pub fn account_path(network: BitcoinNetwork, colored: bool) -> [ChildNumber; 3] {
    [
        ChildNumber::Hardened { index: PURPOSE },
        ChildNumber::Hardened {
            index: coin_type(network, colored),
        },
        ChildNumber::Hardened { index: ACCOUNT },
    ]
}

/// The same path as raw `u32` children (`HARDENED + x`), the form PSBT
/// key-origin metadata and the TypeScript SDK use.
pub fn account_path_u32(network: BitcoinNetwork, colored: bool) -> [u32; 3] {
    account_path(network, colored).map(u32::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_types_match_rgb_lib() {
        assert_eq!(coin_type(BitcoinNetwork::Mainnet, false), 0);
        assert_eq!(coin_type(BitcoinNetwork::Mainnet, true), 827_166);
        for net in [
            BitcoinNetwork::Testnet,
            BitcoinNetwork::Signet,
            BitcoinNetwork::Regtest,
        ] {
            assert_eq!(coin_type(net, false), 1, "{net}");
            assert_eq!(coin_type(net, true), 827_167, "{net}");
        }
    }

    #[test]
    fn account_path_is_hardened_86_coin_0() {
        assert_eq!(
            account_path_u32(BitcoinNetwork::Regtest, false),
            [HARDENED + 86, HARDENED + 1, HARDENED]
        );
        assert_eq!(
            account_path_u32(BitcoinNetwork::Regtest, true),
            [HARDENED + 86, HARDENED + 827_167, HARDENED]
        );
        assert_eq!(
            account_path_u32(BitcoinNetwork::Mainnet, true),
            [HARDENED + 86, HARDENED + 827_166, HARDENED]
        );
        for child in account_path(BitcoinNetwork::Mainnet, false) {
            assert!(child.is_hardened());
        }
        assert_eq!(
            account_path(BitcoinNetwork::Mainnet, false)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["86'", "0'", "0'"]
        );
    }

    #[test]
    fn versions_hrp_and_kind() {
        assert_eq!(BitcoinNetwork::Mainnet.hd_versions().private, 0x0488_ade4);
        assert_eq!(BitcoinNetwork::Mainnet.hd_versions().public, 0x0488_b21e);
        for net in [
            BitcoinNetwork::Testnet,
            BitcoinNetwork::Signet,
            BitcoinNetwork::Regtest,
        ] {
            assert_eq!(net.hd_versions().private, 0x0435_8394);
            assert_eq!(net.hd_versions().public, 0x0435_87cf);
            assert_eq!(net.network_kind(), NetworkKind::Test);
        }
        assert_eq!(BitcoinNetwork::Mainnet.network_kind(), NetworkKind::Main);
        assert_eq!(BitcoinNetwork::Mainnet.bech32_hrp(), "bc");
        assert_eq!(BitcoinNetwork::Testnet.bech32_hrp(), "tb");
        assert_eq!(BitcoinNetwork::Signet.bech32_hrp(), "tb");
        assert_eq!(BitcoinNetwork::Regtest.bech32_hrp(), "bcrt");
        assert_eq!(BitcoinNetwork::Regtest.to_bitcoin(), Network::Regtest);
    }

    #[test]
    fn names_are_distinct_and_display_as_themselves() {
        let names: Vec<&str> = BitcoinNetwork::ALL.iter().map(|n| n.name()).collect();
        assert_eq!(names, ["Mainnet", "Testnet", "Signet", "Regtest"]);
        for net in BitcoinNetwork::ALL {
            assert_eq!(net.to_string(), net.name());
        }
    }
}
