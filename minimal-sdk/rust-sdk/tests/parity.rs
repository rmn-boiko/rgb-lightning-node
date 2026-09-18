//! Parity harness, size gate and dependency-creep guard.
//!
//! Parity rule (non-negotiable): the fixture is read **by relative path** from
//! the TypeScript client SDK. It is never copied, regenerated or replaced by a
//! Rust generator. One rgb-lib-authored ground truth, checked by an
//! implementation that shares no code with it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{Address, ScriptBuf};
use utexo_minimal_sdk::network::HARDENED;
use utexo_minimal_sdk::{
    derive_for_origin_path, derive_taproot, derive_taproot_address, match_origin_path,
    parse_account_xpub, BitcoinNetwork, ClientKeys, ParsedAccounts, SdkError,
};

/// Stripped release cdylib budget. Baseline measured 2026-09-15 on x86_64 for
/// `bitcoin` + `bip39` + uniffi with derive/PSBT/sign reachable: 1.94 MB, of
/// which 1.06 MB is secp256k1 precomputed tables and irreducible.
///
/// Raised 2026-09-18 from 2_500_000 when `get_onchain_operation` was added:
/// the crate then measured 2 493 352 B, so a single new uniffi route — one
/// `Record`, one `Enum` and the lift/lower scaffolding uniffi generates per
/// field — cost 8 648 B and breached a budget with 0.27% headroom. The move to
/// 2.6 MB buys room for roughly ten more routes; it is NOT licence to add a
/// dependency, which the banned-crate guards below still forbid outright.
const SIZE_BUDGET_BYTES: u64 = 2_600_000;

/// Crates that must never appear anywhere in the resolved graph, dev or not.
const BANNED_CRATES: &[&str] = &["rgb-lib", "reqwest", "tokio", "rustls", "openssl"];

/// Crates allowed as dev-dependencies only; they must not reach the library.
const DEV_ONLY_CRATES: &[&str] = &["serde_json"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_path() -> PathBuf {
    manifest_dir().join("../packages/client-sdk/test/fixtures/rgblib-parity.json")
}

fn load_fixture() -> serde_json::Value {
    let path = fixture_path();
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read parity fixture {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("parity fixture {} is not JSON: {e}", path.display()))
}

fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir().join("target"))
}

fn release_cdylib_path() -> PathBuf {
    let name = if cfg!(target_os = "macos") {
        "libutexo_minimal_sdk.dylib"
    } else if cfg!(target_os = "windows") {
        "utexo_minimal_sdk.dll"
    } else {
        "libutexo_minimal_sdk.so"
    };
    target_dir().join("release").join(name)
}

#[test]
fn fixture_is_read_by_relative_path_and_pins_master_fingerprint() {
    let path = fixture_path();
    assert!(
        path.starts_with(manifest_dir().join("..")),
        "fixture must live in the TypeScript client SDK, not in this crate"
    );
    assert!(
        !manifest_dir()
            .join("tests")
            .join("rgblib-parity.json")
            .exists(),
        "do not copy the parity fixture into the Rust crate"
    );

    let fixture = load_fixture();
    let generated_by = fixture["generatedBy"].as_str().unwrap_or_default();
    assert!(
        generated_by.contains("@utexo/rgb-lib"),
        "fixture must be rgb-lib generated, got generatedBy={generated_by:?}"
    );
    let regtest = &fixture["networks"]["Regtest"];
    assert_eq!(regtest["masterFingerprint"].as_str(), Some("73c5da0a"));
    for network in ["Regtest", "Testnet", "Signet", "Mainnet"] {
        let entry = &fixture["networks"][network];
        assert_eq!(
            entry["masterFingerprint"].as_str(),
            Some("73c5da0a"),
            "master fingerprint is network independent ({network})"
        );
        for key in ["accountXpubVanilla", "accountXpubColored"] {
            assert!(
                entry[key].is_string(),
                "{network}.{key} missing from fixture"
            );
        }
    }
}

#[test]
fn size_gate_release_cdylib_under_budget() {
    let status = cargo()
        .args(["build", "--release", "--lib", "--manifest-path"])
        .arg(manifest_dir().join("Cargo.toml"))
        .status()
        .expect("failed to spawn cargo build --release");
    assert!(status.success(), "release build failed");

    let path = release_cdylib_path();
    let bytes = fs::metadata(&path)
        .unwrap_or_else(|e| panic!("release cdylib missing at {}: {e}", path.display()))
        .len();
    println!(
        "size gate: {} = {} bytes ({:.2} MB) of {:.2} MB budget",
        path.display(),
        bytes,
        bytes as f64 / 1_000_000.0,
        SIZE_BUDGET_BYTES as f64 / 1_000_000.0
    );
    assert!(bytes > 0, "release cdylib is empty");
    assert!(
        bytes < SIZE_BUDGET_BYTES,
        "release cdylib {bytes} bytes exceeds budget {SIZE_BUDGET_BYTES}; \
         justify the dependency in the progress notes or drop it"
    );
}

fn lockfile_package_names(lock: &str) -> Vec<String> {
    lock.lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .collect()
}

#[test]
fn dependency_creep_guard() {
    let lock_path = manifest_dir().join("Cargo.lock");
    let lock = fs::read_to_string(&lock_path).expect("Cargo.lock must be committed");
    let names = lockfile_package_names(&lock);
    assert!(
        names.iter().any(|n| n == "utexo-minimal-sdk"),
        "Cargo.lock does not describe this crate"
    );
    for banned in BANNED_CRATES {
        assert!(
            !names.iter().any(|n| n == banned),
            "banned crate `{banned}` is in Cargo.lock (resolved graph)"
        );
    }

    // Library graph only (no dev-dependencies): dev-only helpers must not ship.
    let output = cargo()
        .args([
            "tree",
            "-e",
            "normal",
            "--prefix",
            "none",
            "--locked",
            "--manifest-path",
        ])
        .arg(manifest_dir().join("Cargo.toml"))
        .output()
        .expect("failed to run cargo tree");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    let library_crates: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert!(
        library_crates.contains(&"utexo-minimal-sdk"),
        "cargo tree output did not include the crate:\n{tree}"
    );
    for banned in BANNED_CRATES.iter().chain(DEV_ONLY_CRATES) {
        assert!(
            !library_crates.contains(banned),
            "`{banned}` reached the library dependency graph:\n{tree}"
        );
    }
    println!(
        "dependency guard: {} crates in the library graph",
        library_crates
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
}

#[test]
fn no_udl_file_exists() {
    // Bindings are generated in library mode from proc-macro metadata only.
    let src = manifest_dir().join("src");
    let udl: Vec<PathBuf> = fs::read_dir(&src)
        .expect("src dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "udl"))
        .collect();
    assert!(udl.is_empty(), "UDL files are not allowed: {udl:?}");
    assert!(!Path::new(&manifest_dir().join("src/utexo_minimal_sdk.udl")).exists());
}

// ---------------------------------------------------------------------------
// Task 2: keys — BIP-39 → BIP-32 accounts, checked against rgb-lib's output.
// ---------------------------------------------------------------------------

fn fixture_str<'a>(v: &'a serde_json::Value, what: &str) -> &'a str {
    v.as_str()
        .unwrap_or_else(|| panic!("fixture field {what} is not a string"))
}

fn fixture_mnemonic(fixture: &serde_json::Value) -> String {
    fixture_str(&fixture["mnemonic"], "mnemonic").to_owned()
}

/// Secret-looking substrings that must never appear in any rendered form.
fn secret_markers(mnemonic: &str) -> Vec<String> {
    let mut markers = vec![mnemonic.to_owned()];
    markers.extend(["xprv", "tprv", "SecretKey", "private_key"].map(str::to_owned));
    markers
}

/// No secret marker appears as a substring, and no run of two consecutive
/// mnemonic words appears as consecutive tokens. A single word is not
/// evidence: a random BIP-39 word (`network`, `address`, `fee`, ...) is
/// legitimately a Debug field name or diagnostic word, and generated
/// mnemonics made the single-token form of this check flaky. Any real leak
/// renders the phrase, or at least a run of it, in order.
fn assert_no_secret(rendered: &str, mnemonic: &str, what: &str) {
    for marker in secret_markers(mnemonic) {
        assert!(
            !rendered.contains(&marker),
            "{what} leaks {marker:?}: {rendered}"
        );
    }
    let tokens: Vec<&str> = rendered
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    for pair in words.windows(2) {
        assert!(
            !tokens.windows(2).any(|t| t == pair),
            "{what} leaks mnemonic words {pair:?}: {rendered}"
        );
    }
}

#[test]
fn keys_all_four_networks_match_rgb_lib_fixture_exactly() {
    let fixture = load_fixture();
    let mnemonic = fixture_mnemonic(&fixture);
    for network in BitcoinNetwork::ALL {
        let entry = &fixture["networks"][network.name()];
        assert!(entry.is_object(), "fixture has no entry for {network}");
        let keys = ClientKeys::from_mnemonic(&mnemonic, network)
            .unwrap_or_else(|e| panic!("from_mnemonic failed on {network}: {e}"));
        let xpubs = keys.xpubs();
        assert_eq!(xpubs.network, network);
        assert_eq!(
            xpubs.vanilla,
            fixture_str(&entry["accountXpubVanilla"], "accountXpubVanilla"),
            "{network} vanilla account xpub"
        );
        assert_eq!(
            xpubs.colored,
            fixture_str(&entry["accountXpubColored"], "accountXpubColored"),
            "{network} colored account xpub"
        );
        assert_eq!(
            xpubs.fingerprint,
            fixture_str(&entry["masterFingerprint"], "masterFingerprint"),
            "{network} master fingerprint"
        );
        assert_eq!(keys.fingerprint_hex(), xpubs.fingerprint);
        assert_eq!(keys.network(), network);

        // Serialization version bytes are the network's xpub/tpub bytes.
        let expected_prefix = if network.is_mainnet() { "xpub" } else { "tpub" };
        for xpub in [&xpubs.vanilla, &xpubs.colored] {
            assert!(xpub.starts_with(expected_prefix), "{network}: {xpub}");
            let decoded: Xpub = xpub.parse().expect("our xpub must round-trip");
            let version = u32::from_be_bytes(decoded.encode()[..4].try_into().unwrap());
            assert_eq!(version, network.hd_versions().public, "{network}");
            assert_eq!(decoded.depth, 3, "account xpub is m/86'/coin'/0'");
            assert_eq!(
                decoded.child_number,
                ChildNumber::Hardened { index: 0 },
                "account child is 0'"
            );
        }
    }
}

#[test]
fn keys_fingerprint_is_eight_lowercase_hex_chars() {
    let fixture = load_fixture();
    let keys =
        ClientKeys::from_mnemonic(&fixture_mnemonic(&fixture), BitcoinNetwork::Regtest).unwrap();
    let fp = keys.fingerprint_hex();
    assert_eq!(fp.len(), 8);
    assert!(fp
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(fp, "73c5da0a");
}

#[test]
fn keys_bad_mnemonics_are_rejected_without_detail() {
    let fixture = load_fixture();
    let good = fixture_mnemonic(&fixture);
    let words: Vec<&str> = good.split_whitespace().collect();
    // Bad checksum: swap the last word for a valid word that breaks the checksum.
    let bad_checksum = [&words[..11], &["abandon"]].concat().join(" ");
    // Unknown word, wrong word count, and a 12-word all-valid but wrong-checksum
    // phrase with the last word swapped from a different valid phrase.
    let unknown_word = [&words[..11], &["notaword"]].concat().join(" ");
    let short = words[..11].join(" ");
    let long = [&words[..], &["about"]].concat().join(" ");
    for (label, bad) in [
        ("bad checksum", bad_checksum),
        ("unknown word", unknown_word),
        ("11 words", short),
        ("13 words", long),
        ("empty", String::new()),
    ] {
        for network in BitcoinNetwork::ALL {
            let err = ClientKeys::from_mnemonic(&bad, network)
                .err()
                .unwrap_or_else(|| panic!("{label} accepted on {network}"));
            assert_eq!(err, SdkError::InvalidMnemonic, "{label} on {network}");
            // The error renders nothing about the words supplied.
            let rendered = format!("{err} / {err:?}");
            for word in bad.split_whitespace() {
                assert!(!rendered.contains(word), "{label}: error leaks {word:?}");
            }
        }
    }
    // Whitespace variations of a valid mnemonic are still valid (BIP-39
    // normalization), as in the TypeScript SDK's validateMnemonic.
    let spaced = format!("  {}  ", words.join("   "));
    let a = ClientKeys::from_mnemonic(&spaced, BitcoinNetwork::Regtest).unwrap();
    let b = ClientKeys::from_mnemonic(&good, BitcoinNetwork::Regtest).unwrap();
    assert_eq!(a.xpubs(), b.xpubs());
}

#[test]
fn keys_other_mnemonic_yields_different_material() {
    let fixture = load_fixture();
    let other = fixture_str(&fixture["otherMnemonic"], "otherMnemonic");
    let reference =
        ClientKeys::from_mnemonic(&fixture_mnemonic(&fixture), BitcoinNetwork::Regtest).unwrap();
    let foreign = ClientKeys::from_mnemonic(other, BitcoinNetwork::Regtest)
        .expect("otherMnemonic is a valid BIP-39 phrase");
    assert_ne!(reference.fingerprint_hex(), foreign.fingerprint_hex());
    assert_ne!(reference.xpubs().vanilla, foreign.xpubs().vanilla);
    assert_ne!(reference.xpubs().colored, foreign.xpubs().colored);
    // The colored and vanilla accounts are distinct keys, not aliases.
    assert_ne!(reference.xpubs().vanilla, reference.xpubs().colored);
    // The same mnemonic on mainnet vs regtest: same fingerprint (network
    // independent), different xpubs (different coin types + version bytes).
    let mainnet =
        ClientKeys::from_mnemonic(&fixture_mnemonic(&fixture), BitcoinNetwork::Mainnet).unwrap();
    assert_eq!(mainnet.fingerprint_hex(), reference.fingerprint_hex());
    assert_ne!(mainnet.xpubs().vanilla, reference.xpubs().vanilla);
}

#[test]
fn keys_generate_round_trips_through_from_mnemonic() {
    for network in BitcoinNetwork::ALL {
        let generated = ClientKeys::generate(network).expect("generate");
        assert_eq!(
            generated.mnemonic.split_whitespace().count(),
            12,
            "fresh mnemonics are 12 words"
        );
        let restored = ClientKeys::from_mnemonic(&generated.mnemonic, network).unwrap();
        assert_eq!(restored.xpubs(), generated.keys.xpubs());
        assert_eq!(restored.fingerprint_hex(), generated.keys.fingerprint_hex());
        assert_eq!(generated.keys.network(), network);
        // Two generations never collide.
        let again = ClientKeys::generate(network).unwrap();
        assert_ne!(again.mnemonic, generated.mnemonic);
        assert_ne!(again.keys.xpubs(), generated.keys.xpubs());
    }
    // The exported free function is the same thing.
    let via_ffi = utexo_minimal_sdk::generate_keys(BitcoinNetwork::Regtest).unwrap();
    assert!(ClientKeys::from_mnemonic(&via_ffi.mnemonic, BitcoinNetwork::Regtest).is_ok());
}

#[test]
fn keys_debug_and_xpubs_render_no_secret() {
    let fixture = load_fixture();
    let mnemonic = fixture_mnemonic(&fixture);
    for network in BitcoinNetwork::ALL {
        let keys = ClientKeys::from_mnemonic(&mnemonic, network).unwrap();
        let debug = format!("{keys:?}");
        assert_no_secret(&debug, &mnemonic, "ClientKeys Debug");
        assert!(debug.contains("ClientKeys"), "{debug}");
        assert!(
            debug.contains("73c5da0a"),
            "Debug should still identify the wallet: {debug}"
        );
        let pretty = format!("{keys:#?}");
        assert_no_secret(&pretty, &mnemonic, "ClientKeys pretty Debug");

        let xpubs = keys.xpubs();
        let rendered = format!(
            "{xpubs:?} {} {} {}",
            xpubs.fingerprint, xpubs.vanilla, xpubs.colored
        );
        assert_no_secret(&rendered, &mnemonic, "AccountXpubs");
    }
    // GeneratedKeys deliberately holds the mnemonic; its Debug must not print it.
    let generated = ClientKeys::generate(BitcoinNetwork::Regtest).unwrap();
    let debug = format!("{generated:?}");
    assert_no_secret(&debug, &generated.mnemonic, "GeneratedKeys Debug");
    assert!(debug.contains("[redacted]"), "{debug}");
}

#[test]
fn keys_private_key_for_path_follows_match_origin_path() {
    let fixture = load_fixture();
    let network = BitcoinNetwork::Regtest;
    let keys = ClientKeys::from_mnemonic(&fixture_mnemonic(&fixture), network).unwrap();
    let secp = Secp256k1::new();
    let h = HARDENED;

    // Own paths under both accounts: the private key's public key equals the
    // public derivation from the shared account xpub — proving the xpubs the
    // gateway sees and the keys we sign with are the same accounts.
    for (colored, coin) in [(false, 1u32), (true, 827_167u32)] {
        let xpub: Xpub = if colored {
            keys.xpubs().colored.parse().unwrap()
        } else {
            keys.xpubs().vanilla.parse().unwrap()
        };
        for (keychain, index) in [(0u32, 0u32), (0, 4), (1, 9), (0, 123_456)] {
            let path = [h + 86, h + coin, h, keychain, index];
            let sk = keys
                .private_key_for_path(&path)
                .unwrap_or_else(|| panic!("own path {path:?} rejected"));
            let expected = xpub
                .derive_pub(
                    &secp,
                    &[
                        ChildNumber::from_normal_idx(keychain).unwrap(),
                        ChildNumber::from_normal_idx(index).unwrap(),
                    ],
                )
                .unwrap()
                .public_key;
            assert_eq!(PublicKey::from_secret_key(&secp, &sk), expected, "{path:?}");
        }
    }

    // Foreign paths: None, never an error, never a panic.
    let foreign: &[&[u32]] = &[
        &[],
        &[h + 86, h + 1, h],
        &[h + 86, h + 1, h, 0],
        &[h + 86, h + 1, h, 0, 0, 0],
        &[h + 84, h + 1, h, 0, 0],
        &[h + 86, h, h, 0, 0],           // mainnet coin on regtest keys
        &[h + 86, h + 827_166, h, 0, 0], // mainnet RGB coin on regtest keys
        &[h + 86, h + 1, h + 1, 0, 0],   // account 1'
        &[h + 86, h + 1, h, h, 0],       // hardened keychain
        &[h + 86, h + 1, h, 0, h],       // hardened index
        &[u32::MAX; 5],
    ];
    for path in foreign {
        assert!(keys.private_key_for_path(path).is_none(), "{path:?}");
    }
}

// ---------------------------------------------------------------------------
// Task 3: taproot derivation and origin-path matching, checked against the
// rgb-lib-generated regtest addresses.
// ---------------------------------------------------------------------------

fn fixture_addresses(fixture: &serde_json::Value, key: &str) -> Vec<String> {
    let list = fixture["regtest"][key]
        .as_array()
        .unwrap_or_else(|| panic!("fixture regtest.{key} is not an array"));
    assert_eq!(list.len(), 5, "fixture regtest.{key} has 5 addresses");
    list.iter()
        .enumerate()
        .map(|(i, v)| fixture_str(v, &format!("regtest.{key}[{i}]")).to_owned())
        .collect()
}

fn regtest_accounts(fixture: &serde_json::Value) -> ParsedAccounts {
    let entry = &fixture["networks"]["Regtest"];
    ParsedAccounts {
        network: BitcoinNetwork::Regtest,
        vanilla: parse_account_xpub(
            fixture_str(&entry["accountXpubVanilla"], "accountXpubVanilla"),
            BitcoinNetwork::Regtest,
        )
        .unwrap(),
        colored: parse_account_xpub(
            fixture_str(&entry["accountXpubColored"], "accountXpubColored"),
            BitcoinNetwork::Regtest,
        )
        .unwrap(),
    }
}

#[test]
fn derive_reproduces_rgb_lib_regtest_addresses_at_keychain_0_indexes_0_to_4() {
    let fixture = load_fixture();
    let network = BitcoinNetwork::Regtest;
    let accounts = regtest_accounts(&fixture);
    let entry = &fixture["networks"]["Regtest"];

    for (colored, key) in [(false, "vanillaAddresses"), (true, "coloredAddresses")] {
        let expected = fixture_addresses(&fixture, key);
        let xpub_str = fixture_str(
            &entry[if colored {
                "accountXpubColored"
            } else {
                "accountXpubVanilla"
            }],
            key,
        );
        for (index, address) in expected.iter().enumerate() {
            let index = index as u32;
            let derived = derive_taproot(accounts.account(colored), 0, index, network)
                .unwrap_or_else(|e| panic!("{key}[{index}]: {e}"));
            assert_eq!(&derived.address, address, "{key}[{index}] address");
            assert_eq!(derived.keychain, 0);
            assert_eq!(derived.index, index);

            // The script is the BIP-341 tr(key) output for that address, the
            // internal key is the untweaked x-only key, and both are lowercase hex.
            let parsed: Address = address
                .parse::<Address<_>>()
                .unwrap()
                .require_network(network.to_bitcoin())
                .unwrap();
            let script_hex = parsed.script_pubkey().to_hex_string();
            assert_eq!(derived.script_hex, script_hex, "{key}[{index}] script");
            assert!(derived.script_hex.starts_with("5120"), "OP_1 PUSH32");
            assert_eq!(derived.script_hex.len(), 68);
            assert_eq!(derived.internal_key_hex.len(), 64);
            for hex in [&derived.script_hex, &derived.internal_key_hex] {
                assert!(hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
            }
            let internal: XOnlyPublicKey = derived.internal_key_hex.parse().unwrap();
            let secp = Secp256k1::new();
            assert_eq!(
                ScriptBuf::new_p2tr(&secp, internal, None).to_hex_string(),
                derived.script_hex,
                "internal key tweaks to the output script"
            );
            assert_ne!(
                &derived.script_hex[4..],
                derived.internal_key_hex,
                "output key must be the tweaked key, not the raw internal key"
            );

            // The exported FFI function gives the identical answer from the string xpub.
            assert_eq!(
                derive_taproot_address(xpub_str.to_owned(), 0, index, network).unwrap(),
                derived
            );
        }
    }

    // The vanilla and colored accounts never produce the same address.
    let vanilla = fixture_addresses(&fixture, "vanillaAddresses");
    let colored = fixture_addresses(&fixture, "coloredAddresses");
    assert!(vanilla.iter().all(|a| !colored.contains(a)));
    // Same accounts, other keychain/index: different, still regtest bech32m.
    let other = derive_taproot(&accounts.vanilla, 1, 0, network).unwrap();
    assert!(!vanilla.contains(&other.address));
    assert!(other.address.starts_with("bcrt1p"));
}

#[test]
fn derive_address_hrp_follows_network() {
    let fixture = load_fixture();
    let mnemonic = fixture_mnemonic(&fixture);
    for network in BitcoinNetwork::ALL {
        let keys = ClientKeys::from_mnemonic(&mnemonic, network).unwrap();
        let derived = derive_taproot(&keys.accounts().vanilla, 0, 0, network).unwrap();
        let prefix = format!("{}1p", network.bech32_hrp());
        assert!(
            derived.address.starts_with(&prefix),
            "{network}: {}",
            derived.address
        );
        // Same string xpub through the FFI path; wrong-network xpub is refused.
        let xpubs = keys.xpubs();
        assert_eq!(
            derive_taproot_address(xpubs.vanilla.clone(), 0, 0, network).unwrap(),
            derived
        );
        let other = if network.is_mainnet() {
            BitcoinNetwork::Regtest
        } else {
            BitcoinNetwork::Mainnet
        };
        assert!(matches!(
            derive_taproot_address(xpubs.vanilla.clone(), 0, 0, other),
            Err(SdkError::InvalidInput { .. })
        ));
    }
    // Hardened keychain/index through the FFI surface: an error, never a panic.
    let keys = ClientKeys::from_mnemonic(&mnemonic, BitcoinNetwork::Regtest).unwrap();
    let xpub = keys.xpubs().vanilla;
    assert!(matches!(
        derive_taproot_address(xpub.clone(), HARDENED, 0, BitcoinNetwork::Regtest),
        Err(SdkError::DerivationFailed { .. })
    ));
    assert!(matches!(
        derive_taproot_address(xpub, 0, HARDENED, BitcoinNetwork::Regtest),
        Err(SdkError::DerivationFailed { .. })
    ));
    assert!(matches!(
        derive_taproot_address("garbage".into(), 0, 0, BitcoinNetwork::Regtest),
        Err(SdkError::InvalidInput { .. })
    ));
}

#[test]
fn derive_for_origin_path_re_derives_rgb_lib_addresses_and_rejects_foreign_paths() {
    let fixture = load_fixture();
    let network = BitcoinNetwork::Regtest;
    let accounts = regtest_accounts(&fixture);
    let h = HARDENED;
    let vanilla_path = [h + 86, h + 1, h];
    let colored_path = [h + 86, h + 827_167, h];
    let vanilla = fixture_addresses(&fixture, "vanillaAddresses");
    let colored = fixture_addresses(&fixture, "coloredAddresses");

    for index in 0..5u32 {
        let v = derive_for_origin_path(
            &[vanilla_path[0], vanilla_path[1], vanilla_path[2], 0, index],
            &accounts,
            network,
        )
        .unwrap();
        assert_eq!(v.address, vanilla[index as usize]);
        let c = derive_for_origin_path(
            &[colored_path[0], colored_path[1], colored_path[2], 0, index],
            &accounts,
            network,
        )
        .unwrap();
        assert_eq!(c.address, colored[index as usize]);
    }
    // ClientKeys::accounts() is the same public material.
    let keys = ClientKeys::from_mnemonic(&fixture_mnemonic(&fixture), network).unwrap();
    assert_eq!(keys.accounts(), accounts);

    let foreign: &[&[u32]] = &[
        &[],
        &[h + 84, h + 1, h, 0, 0],
        &[h + 86, h + 1, h, 0],
        &[h + 86, h + 1, h, h, 0],
        &[h + 86, h + 1, h, 0, h],
        &[h + 86, h + 1, h, 0, 0, 0],
        &[h + 86, h, h, 0, 0],
        &[h + 86, h + 827_166, h, 0, 0],
        &[h + 86, h + 1, h + 1, 0, 0],
    ];
    for path in foreign {
        assert!(
            derive_for_origin_path(path, &accounts, network).is_none(),
            "{path:?}"
        );
    }
}

#[test]
fn match_origin_path_accepts_both_accounts_and_rejects_everything_else() {
    let h = HARDENED;
    for network in BitcoinNetwork::ALL {
        let (btc, rgb) = if network.is_mainnet() {
            (0u32, 827_166u32)
        } else {
            (1u32, 827_167u32)
        };
        let v = match_origin_path(&[h + 86, h + btc, h, 0, 5], network).unwrap();
        assert!(!v.colored);
        assert_eq!((v.keychain, v.index), (0, 5));
        let c = match_origin_path(&[h + 86, h + rgb, h, 1, h - 1], network).unwrap();
        assert!(c.colored);
        assert_eq!((c.keychain, c.index), (1, h - 1));

        let rejected: Vec<Vec<u32>> = vec![
            vec![],                                // empty
            vec![h + 86, h + btc, h],              // account only
            vec![h + 86, h + btc, h, 0],           // short
            vec![h + 86, h + btc, h, 0, 0, 0],     // over-long
            vec![h + 84, h + btc, h, 0, 0],        // wrong purpose
            vec![86, h + btc, h, 0, 0],            // unhardened purpose
            vec![h + 86, h + btc + 2, h, 0, 0],    // wrong coin
            vec![h + 86, btc, h, 0, 0],            // unhardened coin
            vec![h + 86, h + btc, h + 1, 0, 0],    // wrong account
            vec![h + 86, h + btc, 0, 0, 0],        // unhardened account
            vec![h + 86, h + btc, h, h, 0],        // hardened keychain
            vec![h + 86, h + btc, h, 0, h],        // hardened index
            vec![h + 86, h + rgb, h, u32::MAX, 0], // hardened keychain (colored)
            vec![h + 86, h + rgb, h, 0, u32::MAX], // hardened index (colored)
            vec![u32::MAX; 5],
        ];
        for path in &rejected {
            assert_eq!(match_origin_path(path, network), None, "{network} {path:?}");
        }
        // The other network's coin types are foreign here.
        let (obtc, orgb) = if network.is_mainnet() {
            (1, 827_167)
        } else {
            (0, 827_166)
        };
        assert_eq!(
            match_origin_path(&[h + 86, h + obtc, h, 0, 0], network),
            None
        );
        assert_eq!(
            match_origin_path(&[h + 86, h + orgb, h, 0, 0], network),
            None
        );
    }
}

#[test]
fn private_key_for_path_signs_exactly_what_verify_re_derives() {
    // The property the single-source-of-truth design exists for: for every
    // path, `private_key_for_path` returns a key iff `match_origin_path`
    // accepts it, and that key's x-only public key is precisely the internal
    // key `derive_for_origin_path` (verify's view) re-derives for the path.
    let fixture = load_fixture();
    let mnemonic = fixture_mnemonic(&fixture);
    let secp = Secp256k1::new();
    let h = HARDENED;
    for network in BitcoinNetwork::ALL {
        let keys = ClientKeys::from_mnemonic(&mnemonic, network).unwrap();
        let accounts = keys.accounts();
        let (btc, rgb) = if network.is_mainnet() {
            (0u32, 827_166u32)
        } else {
            (1u32, 827_167u32)
        };
        let mut paths: Vec<Vec<u32>> = vec![
            vec![],
            vec![h + 86, h + btc, h],
            vec![h + 86, h + btc, h, 0],
            vec![h + 86, h + btc, h, 0, 0, 0],
            vec![h + 84, h + btc, h, 0, 0],
            vec![h + 86, h + btc, h + 1, 0, 0],
            vec![h + 86, h + btc, h, h, 0],
            vec![h + 86, h + btc, h, 0, h],
            vec![h + 86, h + btc + 2, h, 0, 0],
        ];
        for coin in [btc, rgb] {
            for (keychain, index) in [(0, 0), (0, 4), (1, 0), (1, 7), (9, 123_456), (0, h - 1)] {
                paths.push(vec![h + 86, h + coin, h, keychain, index]);
            }
        }
        let mut accepted = 0;
        for path in &paths {
            let matched = match_origin_path(path, network);
            let sk = keys.private_key_for_path(path);
            let derived = derive_for_origin_path(path, &accounts, network);
            assert_eq!(matched.is_some(), sk.is_some(), "{network} {path:?}");
            assert_eq!(matched.is_some(), derived.is_some(), "{network} {path:?}");
            if let (Some(sk), Some(derived)) = (sk, derived) {
                accepted += 1;
                let (xonly, _) = PublicKey::from_secret_key(&secp, &sk).x_only_public_key();
                assert_eq!(
                    xonly.serialize().to_vec(),
                    hex_decode(&derived.internal_key_hex),
                    "{network} {path:?}: signing key != verified internal key"
                );
                let m = matched.unwrap();
                assert_eq!((m.keychain, m.index), (derived.keychain, derived.index));
            }
        }
        assert_eq!(accepted, 12, "{network}: 6 own paths per account");
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// Task 4: verify-before-sign — the five checks, against the rgb-lib fixture
// PSBT and adversarial PSBTs built here. Each attack must trip exactly the
// check that owns it; hostile bytes must never panic or error.
// ---------------------------------------------------------------------------

mod psbt_builder {
    //! A PSBT builder with full control over scripts and key-origin metadata,
    //! mirroring `minimal-sdk/packages/client-sdk/test/helpers.ts`. Metadata
    //! is attacker-controlled in the threat model, so this deliberately lets
    //! a test attach any fingerprint/path/key to any input or output.

    use bitcoin::absolute::LockTime;
    use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
    use bitcoin::hashes::Hash;
    use bitcoin::key::XOnlyPublicKey;
    use bitcoin::psbt::Psbt;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use utexo_minimal_sdk::network::HARDENED;
    use utexo_minimal_sdk::{derive_taproot, BitcoinNetwork, ClientKeys};

    pub const NETWORK: BitcoinNetwork = BitcoinNetwork::Regtest;
    /// Vanilla-account path children on regtest: m/86'/1'/0'.
    pub const VANILLA_PATH: [u32; 3] = [HARDENED + 86, HARDENED + 1, HARDENED];
    /// Colored-account path children on regtest: m/86'/827167'/0'.
    pub const COLORED_PATH: [u32; 3] = [HARDENED + 86, HARDENED + 827_167, HARDENED];

    /// Standard zero-value OP_RETURN output used across cases.
    pub fn opret_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x6a, 0x05, 1, 2, 3, 4, 5])
    }

    /// A test wallet: the script and internal key at any keychain/index of
    /// either account, plus the master fingerprint.
    pub struct TestWallet {
        pub keys: ClientKeys,
    }

    impl TestWallet {
        pub fn from_mnemonic(mnemonic: &str) -> Self {
            TestWallet {
                keys: ClientKeys::from_mnemonic(mnemonic, NETWORK).expect("fixture mnemonic"),
            }
        }

        pub fn fingerprint(&self) -> Fingerprint {
            self.keys.fingerprint()
        }

        pub fn script_at(&self, colored: bool, keychain: u32, index: u32) -> ScriptBuf {
            let derived = derive_taproot(
                self.keys.accounts().account(colored),
                keychain,
                index,
                NETWORK,
            )
            .expect("unhardened derivation");
            ScriptBuf::from_hex(&derived.script_hex).unwrap()
        }

        pub fn address_at(&self, colored: bool, keychain: u32, index: u32) -> String {
            derive_taproot(
                self.keys.accounts().account(colored),
                keychain,
                index,
                NETWORK,
            )
            .expect("unhardened derivation")
            .address
        }

        pub fn xonly_at(&self, colored: bool, keychain: u32, index: u32) -> XOnlyPublicKey {
            let derived = derive_taproot(
                self.keys.accounts().account(colored),
                keychain,
                index,
                NETWORK,
            )
            .expect("unhardened derivation");
            derived.internal_key_hex.parse().unwrap()
        }

        /// Key-origin metadata claiming this wallet owns `keychain/index`.
        pub fn origin(&self, colored: bool, keychain: u32, index: u32) -> KeyOrigin {
            let account = if colored { COLORED_PATH } else { VANILLA_PATH };
            KeyOrigin {
                fingerprint: self.fingerprint(),
                path: [account[0], account[1], account[2], keychain, index].to_vec(),
                xonly: self.xonly_at(colored, keychain, index),
            }
        }
    }

    #[derive(Clone)]
    pub struct KeyOrigin {
        pub fingerprint: Fingerprint,
        pub path: Vec<u32>,
        pub xonly: XOnlyPublicKey,
    }

    impl KeyOrigin {
        pub fn derivation_path(&self) -> DerivationPath {
            self.path
                .iter()
                .map(|&c| ChildNumber::from(c))
                .collect::<Vec<_>>()
                .into()
        }
    }

    pub struct InputSpec {
        /// Script actually being spent.
        pub script: ScriptBuf,
        pub amount: u64,
        /// Key-origin entries to attach, decoys included (the map is keyed
        /// by x-only key, so a decoy must carry a distinct key).
        pub origins: Vec<KeyOrigin>,
        pub tap_internal_key: Option<XOnlyPublicKey>,
    }

    impl InputSpec {
        pub fn new(script: ScriptBuf, amount: u64, origin: Option<KeyOrigin>) -> Self {
            InputSpec {
                script,
                amount,
                origins: origin.into_iter().collect(),
                tap_internal_key: None,
            }
        }
    }

    pub struct OutputSpec {
        pub script: ScriptBuf,
        pub amount: u64,
        pub origin: Option<KeyOrigin>,
    }

    impl OutputSpec {
        pub fn new(script: ScriptBuf, amount: u64, origin: Option<KeyOrigin>) -> Self {
            OutputSpec {
                script,
                amount,
                origin,
            }
        }
    }

    /// Build a base64 PSBT: v2 transaction, synthetic outpoints, and exactly
    /// the metadata each spec asks for. No sanity checks — hostile-server
    /// emulation.
    pub fn build_psbt(inputs: &[InputSpec], outputs: &[OutputSpec]) -> String {
        build_psbt_raw(inputs, outputs).to_string()
    }

    pub fn build_psbt_raw(inputs: &[InputSpec], outputs: &[OutputSpec]) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .enumerate()
                .map(|(i, _)| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([(i + 1) as u8; 32]),
                        vout: i as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .iter()
                .map(|o| TxOut {
                    value: Amount::from_sat(o.amount),
                    script_pubkey: o.script.clone(),
                })
                .collect(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        for (spec, input) in inputs.iter().zip(psbt.inputs.iter_mut()) {
            input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(spec.amount),
                script_pubkey: spec.script.clone(),
            });
            input.tap_internal_key = spec.tap_internal_key;
            for origin in &spec.origins {
                input.tap_key_origins.insert(
                    origin.xonly,
                    (Vec::new(), (origin.fingerprint, origin.derivation_path())),
                );
            }
        }
        for (spec, output) in outputs.iter().zip(psbt.outputs.iter_mut()) {
            if let Some(origin) = &spec.origin {
                output.tap_internal_key = Some(origin.xonly);
                output.tap_key_origins.insert(
                    origin.xonly,
                    (Vec::new(), (origin.fingerprint, origin.derivation_path())),
                );
            }
        }
        psbt
    }
}

use bitcoin::psbt::Psbt;
use psbt_builder::{
    build_psbt, build_psbt_raw, opret_script, InputSpec, KeyOrigin, OutputSpec, TestWallet,
};
use utexo_minimal_sdk::{
    own_derivation, verify_psbt, CheckName, IntentAsset, IntentKind, IntentRecipient, IntentUtxos,
    OnchainIntent, VerifyParams, VerifyVerdict,
};

struct Wallets {
    ours: TestWallet,
    foreign: TestWallet,
    fixture: serde_json::Value,
}

fn wallets() -> Wallets {
    let fixture = load_fixture();
    let ours = TestWallet::from_mnemonic(&fixture_mnemonic(&fixture));
    let foreign =
        TestWallet::from_mnemonic(fixture_str(&fixture["otherMnemonic"], "otherMnemonic"));
    assert_ne!(ours.fingerprint(), foreign.fingerprint());
    Wallets {
        ours,
        foreign,
        fixture,
    }
}

/// The intent the rgb-lib fixture PSBT was prepared for: 40 000 sat to the
/// foreign wallet's vanilla address 0 (`test/sign.test.ts`).
fn send_btc_intent(w: &Wallets) -> OnchainIntent {
    OnchainIntent {
        kind: IntentKind::SendBtc,
        fee_rate_sat_per_vb: 2,
        recipients: vec![IntentRecipient {
            address: w.foreign.address_at(false, 0, 0),
            script_hex: w.foreign.script_at(false, 0, 0).to_hex_string(),
            amount_sat: 40_000,
        }],
        asset: None,
        utxos: None,
    }
}

fn params(w: &Wallets, intent: OnchainIntent, max_fee_sat: u64) -> VerifyParams {
    VerifyParams {
        intent,
        xpubs: w.ours.keys.xpubs(),
        max_fee_sat,
        change_scan_window: None,
        max_own_output_index: None,
    }
}

fn check(verdict: &VerifyVerdict, name: CheckName) -> &utexo_minimal_sdk::CheckResult {
    verdict
        .check(name)
        .unwrap_or_else(|| panic!("verdict has no {name} check: {verdict:?}"))
}

fn detail(verdict: &VerifyVerdict, name: CheckName) -> String {
    check(verdict, name).detail.clone().unwrap_or_default()
}

/// Assert exactly `expected` failed, every other check passed, and the
/// verdict is not ok (unless `expected` is empty).
fn assert_only_fails(verdict: &VerifyVerdict, expected: &[CheckName]) {
    assert_eq!(verdict.checks.len(), 5, "{verdict:?}");
    assert_eq!(
        verdict.checks.iter().map(|c| c.check).collect::<Vec<_>>(),
        CheckName::ALL,
        "checks are always listed in evaluation order"
    );
    assert_eq!(verdict.failed(), expected, "{verdict:#?}");
    assert_eq!(verdict.ok, expected.is_empty(), "{verdict:#?}");
    for c in &verdict.checks {
        assert_eq!(c.detail.is_some(), !c.ok, "detail iff failed: {c:?}");
    }
}

fn assert_all_pass(verdict: &VerifyVerdict) {
    assert_only_fails(verdict, &[]);
}

struct Happy {
    change_script: Option<bitcoin::ScriptBuf>,
    change_origin: Option<Option<KeyOrigin>>,
    change_amount: u64,
    opret_amount: u64,
    extra_outputs: Vec<OutputSpec>,
    input_origins: Option<Vec<KeyOrigin>>,
    input_internal_key: Option<bitcoin::key::XOnlyPublicKey>,
}

impl Happy {
    fn default() -> Self {
        Happy {
            change_script: None,
            change_origin: None,
            change_amount: 59_000,
            opret_amount: 0,
            extra_outputs: Vec::new(),
            input_origins: None,
            input_internal_key: None,
        }
    }
}

/// Happy-path shape, same as `test/verify.test.ts` `happyPsbt`: own input
/// 100 000 sat at vanilla 0/0, intended recipient 40 000, own change 59 000
/// at vanilla 0/1, 0-sat OP_RETURN. Fee 1 000.
fn happy_psbt(w: &Wallets, h: Happy) -> String {
    let mut input = InputSpec::new(
        w.ours.script_at(false, 0, 0),
        100_000,
        Some(w.ours.origin(false, 0, 0)),
    );
    if let Some(origins) = h.input_origins {
        input.origins = origins;
    }
    input.tap_internal_key = h.input_internal_key;
    let mut outputs = vec![
        OutputSpec::new(w.foreign.script_at(false, 0, 0), 40_000, None),
        OutputSpec::new(
            h.change_script
                .unwrap_or_else(|| w.ours.script_at(false, 0, 1)),
            h.change_amount,
            h.change_origin
                .unwrap_or_else(|| Some(w.ours.origin(false, 0, 1))),
        ),
        OutputSpec::new(opret_script(), h.opret_amount, None),
    ];
    outputs.extend(h.extra_outputs);
    build_psbt(&[input], &outputs)
}

#[test]
fn psbt_deserialize_preserves_every_tap_key_origin_entry_including_decoys() {
    // The decoy defence depends on `tap_key_origins` surviving a round trip
    // with a foreign-fingerprint entry alongside ours on the same input, and
    // on outputs. Proved rather than assumed.
    let w = wallets();
    let ours = w.ours.origin(false, 0, 0);
    let decoy = w.foreign.origin(false, 0, 1);
    let decoy2 = w.foreign.origin(true, 0, 0);
    let mut input = InputSpec::new(w.ours.script_at(false, 0, 0), 100_000, None);
    input.origins = vec![decoy.clone(), ours.clone(), decoy2.clone()];
    input.tap_internal_key = Some(ours.xonly);
    let psbt_b64 = build_psbt(
        &[input],
        &[OutputSpec::new(
            w.ours.script_at(false, 0, 1),
            99_000,
            Some(w.ours.origin(false, 0, 1)),
        )],
    );

    let parsed: Psbt = psbt_b64.parse().expect("round trip");
    let origins = &parsed.inputs[0].tap_key_origins;
    assert_eq!(origins.len(), 3, "all three entries survive: {origins:?}");
    for entry in [&decoy, &ours, &decoy2] {
        let (_, (fp, path)) = origins
            .get(&entry.xonly)
            .unwrap_or_else(|| panic!("entry {} missing", entry.xonly));
        assert_eq!(*fp, entry.fingerprint);
        assert_eq!(path.to_u32_vec(), entry.path);
    }
    assert_eq!(parsed.inputs[0].tap_internal_key, Some(ours.xonly));
    assert_eq!(
        parsed.inputs[0]
            .witness_utxo
            .as_ref()
            .map(|u| u.value.to_sat()),
        Some(100_000)
    );
    assert_eq!(parsed.outputs[0].tap_key_origins.len(), 1);
    // Byte-exact re-serialization: nothing is dropped or reordered.
    assert_eq!(parsed.to_string(), psbt_b64);
    assert_eq!(Psbt::deserialize(&parsed.serialize()).unwrap(), parsed);

    // `own_derivation` on the parsed map picks ours regardless of key order.
    let (key, source) = own_derivation(origins, w.ours.fingerprint()).expect("ours");
    assert_eq!(key, ours.xonly);
    assert_eq!(source.1.to_u32_vec(), ours.path);
    let (dkey, _) = own_derivation(origins, w.foreign.fingerprint()).expect("theirs");
    assert!(dkey == decoy.xonly || dkey == decoy2.xonly);
}

#[test]
fn verify_fixture_psbt_passes_all_five_checks_with_rgb_lib_txid() {
    let w = wallets();
    let unsigned = fixture_str(
        &w.fixture["signing"]["unsignedPsbt"],
        "signing.unsignedPsbt",
    );
    let verdict = verify_psbt(unsigned, &params(&w, send_btc_intent(&w), 2_000));
    assert_all_pass(&verdict);
    assert_eq!(verdict.fee_sat, Some(1_000));
    assert_eq!(
        verdict.txid.as_deref(),
        Some(fixture_str(&w.fixture["signing"]["txid"], "signing.txid"))
    );
    // Same answer through the exported function with owned values.
    let via_ffi = utexo_minimal_sdk::ffi::ffi_verify_psbt(
        unsigned.to_owned(),
        params(&w, send_btc_intent(&w), 2_000),
    );
    assert_eq!(via_ffi, verdict);
    // The fixture PSBT has the rgb-lib shape: metadata on input 0 and on the
    // change output, both under our fingerprint.
    let parsed: Psbt = unsigned.parse().unwrap();
    assert!(own_derivation(&parsed.inputs[0].tap_key_origins, w.ours.fingerprint()).is_some());
    assert!(own_derivation(&parsed.outputs[1].tap_key_origins, w.ours.fingerprint()).is_some());
    // Nothing rendered from a verdict ever carries key material.
    let mnemonic = fixture_mnemonic(&w.fixture);
    assert_no_secret(&format!("{verdict:?}"), &mnemonic, "VerifyVerdict Debug");
    assert_no_secret(
        &format!("{:?}", params(&w, send_btc_intent(&w), 2_000)),
        &mnemonic,
        "VerifyParams Debug",
    );
}

#[test]
fn verify_happy_psbt_built_here_matches_the_fixture_shape() {
    let w = wallets();
    let verdict = verify_psbt(
        &happy_psbt(&w, Happy::default()),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_all_pass(&verdict);
    assert_eq!(verdict.fee_sat, Some(1_000));
    assert_eq!(verdict.txid.as_ref().map(String::len), Some(64));

    // Colored-keychain input and change (blind asset send): all pass.
    let blind = OnchainIntent {
        kind: IntentKind::SendAsset,
        fee_rate_sat_per_vb: 2,
        recipients: vec![],
        asset: Some(IntentAsset {
            asset_id: "rgb:fixture".into(),
            amount: 5,
            recipient_id: "bcrt:utxob:fixture".into(),
            witness_amount_sat: None,
            transport_endpoints: vec!["rpc://localhost:3000/json-rpc".into()],
        }),
        utxos: None,
    };
    let colored = build_psbt(
        &[InputSpec::new(
            w.ours.script_at(true, 0, 0),
            30_000,
            Some(w.ours.origin(true, 0, 0)),
        )],
        &[
            OutputSpec::new(
                w.ours.script_at(true, 0, 1),
                29_000,
                Some(w.ours.origin(true, 0, 1)),
            ),
            OutputSpec::new(opret_script(), 0, None),
        ],
    );
    assert_all_pass(&verify_psbt(&colored, &params(&w, blind, 2_000)));
}

#[test]
fn check1_foreign_input_fails_only_inputs_own() {
    let w = wallets();
    // (a) Our script, but the only key origin carries the OTHER mnemonic's
    // fingerprint: not provably ours.
    let mut foreign_fp = w.foreign.origin(false, 0, 0);
    foreign_fp.path = w.ours.origin(false, 0, 0).path;
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                input_origins: Some(vec![foreign_fp]),
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::InputsOwn]);
    assert!(detail(&verdict, CheckName::InputsOwn).contains("foreign input"));

    // (b) Attacker spends THEIR utxo but labels it with our fingerprint/path.
    let psbt = build_psbt(
        &[InputSpec::new(
            w.foreign.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 40_000, None),
            OutputSpec::new(
                w.ours.script_at(false, 0, 1),
                59_000,
                Some(w.ours.origin(false, 0, 1)),
            ),
        ],
    );
    let verdict = verify_psbt(&psbt, &params(&w, send_btc_intent(&w), 2_000));
    assert_only_fails(&verdict, &[CheckName::InputsOwn]);
    assert!(detail(&verdict, CheckName::InputsOwn).contains("does not re-derive"));

    // (c) Our fingerprint on a path outside our accounts (account 1').
    let mut odd = w.ours.origin(false, 0, 0);
    odd.path[2] = HARDENED + 1;
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                input_origins: Some(vec![odd]),
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::InputsOwn]);
    assert!(detail(&verdict, CheckName::InputsOwn).contains("not under our accounts"));

    // (d) No metadata at all.
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                input_origins: Some(vec![]),
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::InputsOwn]);

    // (e) Forged tapInternalKey that does not match the re-derived key.
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                input_internal_key: Some(w.ours.xonly_at(false, 0, 4)),
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::InputsOwn]);
    assert!(detail(&verdict, CheckName::InputsOwn).contains("tapInternalKey mismatch"));
    // ...while the genuine internal key passes.
    assert_all_pass(&verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                input_internal_key: Some(w.ours.xonly_at(false, 0, 0)),
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    ));

    // (f) No witness_utxo: cannot know what is being spent.
    let mut psbt = build_psbt_raw(
        &[InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[OutputSpec::new(
            w.ours.script_at(false, 0, 1),
            99_000,
            Some(w.ours.origin(false, 0, 1)),
        )],
    );
    psbt.inputs[0].witness_utxo = None;
    let intent = OnchainIntent {
        recipients: vec![],
        ..send_btc_intent(&w)
    };
    let verdict = verify_psbt(&psbt.to_string(), &params(&w, intent, 2_000));
    assert!(detail(&verdict, CheckName::InputsOwn).contains("no witnessUtxo"));
    assert!(verdict.failed().contains(&CheckName::InputsOwn));

    // (g) Own inputs are NOT restricted to keychain 0 or a bounded index:
    // spending from an odd path is proven safe by re-derivation alone.
    let odd_input = InputSpec::new(
        w.ours.script_at(false, 7, 900_000_000),
        100_000,
        Some(w.ours.origin(false, 7, 900_000_000)),
    );
    let psbt = build_psbt(
        &[odd_input],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 40_000, None),
            OutputSpec::new(
                w.ours.script_at(false, 0, 1),
                59_000,
                Some(w.ours.origin(false, 0, 1)),
            ),
        ],
    );
    assert_all_pass(&verify_psbt(&psbt, &params(&w, send_btc_intent(&w), 2_000)));
}

#[test]
fn check1_inputless_transaction_fails_closed() {
    let w = wallets();
    let psbt = build_psbt(
        &[],
        &[OutputSpec::new(
            w.foreign.script_at(false, 0, 0),
            40_000,
            None,
        )],
    );
    let verdict = verify_psbt(&psbt, &params(&w, send_btc_intent(&w), 2_000));
    assert!(!check(&verdict, CheckName::InputsOwn).ok);
    assert!(detail(&verdict, CheckName::InputsOwn).contains("no inputs"));
    assert!(!verdict.ok);
    assert_eq!(verdict.fee_sat, Some(-40_000));
}

/// A self-send: the intended recipient is one of OUR keychain-0 addresses,
/// carrying metadata. Tampering the intent then trips check 2 alone, because
/// the mismatched output still proves ownership under check 3.
fn self_send(w: &Wallets) -> (String, OnchainIntent) {
    let psbt = build_psbt(
        &[InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(
                w.ours.script_at(false, 0, 2),
                40_000,
                Some(w.ours.origin(false, 0, 2)),
            ),
            OutputSpec::new(
                w.ours.script_at(false, 0, 1),
                59_000,
                Some(w.ours.origin(false, 0, 1)),
            ),
            OutputSpec::new(opret_script(), 0, None),
        ],
    );
    let intent = OnchainIntent {
        kind: IntentKind::SendBtc,
        fee_rate_sat_per_vb: 2,
        recipients: vec![IntentRecipient {
            address: w.ours.address_at(false, 0, 2),
            script_hex: w.ours.script_at(false, 0, 2).to_hex_string(),
            amount_sat: 40_000,
        }],
        asset: None,
        utxos: None,
    };
    (psbt, intent)
}

#[test]
fn check2_tampered_recipient_amount_fails_only_recipients_match() {
    let w = wallets();
    let (psbt, mut intent) = self_send(&w);
    assert_all_pass(&verify_psbt(&psbt, &params(&w, intent.clone(), 2_000)));
    intent.recipients[0].amount_sat = 39_000;
    let verdict = verify_psbt(&psbt, &params(&w, intent, 2_000));
    assert_only_fails(&verdict, &[CheckName::RecipientsMatch]);
    assert!(detail(&verdict, CheckName::RecipientsMatch).contains("no output pays 39000 sat"));

    // The realistic case on the rgb-lib fixture PSBT: the intent's amount is
    // tampered, so recipients-match fails, and the now-unaccounted foreign
    // output is flagged by change-own too (defence in depth).
    let unsigned = fixture_str(
        &w.fixture["signing"]["unsignedPsbt"],
        "signing.unsignedPsbt",
    );
    let mut tampered = send_btc_intent(&w);
    tampered.recipients[0].amount_sat = 39_000;
    let verdict = verify_psbt(unsigned, &params(&w, tampered, 2_000));
    assert_eq!(
        verdict.failed(),
        [CheckName::RecipientsMatch, CheckName::ChangeOwn]
    );
    // PSBT-side amount tampering (recipient paid 90 000, change 9 000).
    let psbt = build_psbt(
        &[InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 90_000, None),
            OutputSpec::new(
                w.ours.script_at(false, 0, 1),
                9_000,
                Some(w.ours.origin(false, 0, 1)),
            ),
        ],
    );
    let verdict = verify_psbt(&psbt, &params(&w, send_btc_intent(&w), 2_000));
    assert!(!check(&verdict, CheckName::RecipientsMatch).ok);
    assert!(!verdict.ok);
}

#[test]
fn check2_tampered_recipient_address_fails_only_recipients_match() {
    let w = wallets();
    let (psbt, mut intent) = self_send(&w);
    // Intent names a different (own) address, consistent with its script.
    intent.recipients[0].address = w.ours.address_at(false, 0, 3);
    intent.recipients[0].script_hex = w.ours.script_at(false, 0, 3).to_hex_string();
    let verdict = verify_psbt(&psbt, &params(&w, intent, 2_000));
    assert_only_fails(&verdict, &[CheckName::RecipientsMatch]);
    assert!(detail(&verdict, CheckName::RecipientsMatch).contains("no output pays"));

    // Swapped recipient script in the PSBT (payment redirected).
    let swapped = build_psbt(
        &[InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 4), 40_000, None),
            OutputSpec::new(
                w.ours.script_at(false, 0, 1),
                59_000,
                Some(w.ours.origin(false, 0, 1)),
            ),
            OutputSpec::new(opret_script(), 0, None),
        ],
    );
    let verdict = verify_psbt(&swapped, &params(&w, send_btc_intent(&w), 2_000));
    assert!(!check(&verdict, CheckName::RecipientsMatch).ok);
    assert!(!verdict.ok);

    // An undecodable intent address fails instead of being trusted.
    let mut bad = send_btc_intent(&w);
    bad.recipients[0].address = "not-an-address".into();
    let verdict = verify_psbt(&happy_psbt(&w, Happy::default()), &params(&w, bad, 2_000));
    assert!(!check(&verdict, CheckName::RecipientsMatch).ok);
    assert!(detail(&verdict, CheckName::RecipientsMatch).contains("does not decode"));

    // A mainnet address for the same key does not decode on regtest.
    let mut wrong_net = send_btc_intent(&w);
    let key = w.foreign.xonly_at(false, 0, 0);
    wrong_net.recipients[0].address =
        bitcoin::Address::p2tr(&Secp256k1::new(), key, None, bitcoin::Network::Bitcoin).to_string();
    let verdict = verify_psbt(
        &happy_psbt(&w, Happy::default()),
        &params(&w, wrong_net, 2_000),
    );
    assert!(detail(&verdict, CheckName::RecipientsMatch).contains("does not decode on Regtest"));
}

#[test]
fn check2_intent_script_hex_contradicting_its_address_fails_recipients_match() {
    let w = wallets();
    // A compromised gateway shows the user the REAL recipient address but
    // pairs it with an attacker script and a PSBT paying that script. The
    // expected script must be re-derived from the address, never trusted.
    let attacker_script = w.foreign.script_at(false, 0, 4);
    let mut hostile = send_btc_intent(&w);
    hostile.recipients[0].script_hex = attacker_script.to_hex_string();
    let psbt = build_psbt(
        &[InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(attacker_script, 40_000, None),
            OutputSpec::new(
                w.ours.script_at(false, 0, 1),
                59_000,
                Some(w.ours.origin(false, 0, 1)),
            ),
            OutputSpec::new(opret_script(), 0, None),
        ],
    );
    let verdict = verify_psbt(&psbt, &params(&w, hostile.clone(), 2_000));
    assert!(!check(&verdict, CheckName::RecipientsMatch).ok);
    assert!(detail(&verdict, CheckName::RecipientsMatch).contains("does not match"));
    assert!(!verdict.ok);

    // Isolated: same contradiction on a self-send trips only check 2.
    let (psbt, mut intent) = self_send(&w);
    intent.recipients[0].script_hex = w.ours.script_at(false, 0, 1).to_hex_string();
    let verdict = verify_psbt(&psbt, &params(&w, intent.clone(), 2_000));
    assert_only_fails(&verdict, &[CheckName::RecipientsMatch]);
    // Case-insensitive script_hex comparison, as in the TypeScript SDK.
    intent.recipients[0].script_hex = w.ours.script_at(false, 0, 2).to_hex_string().to_uppercase();
    assert_all_pass(&verify_psbt(&psbt, &params(&w, intent, 2_000)));
}

#[test]
fn check2_recipients_are_matched_as_a_multiset() {
    let w = wallets();
    // Two identical recipients need two outputs; one output cannot satisfy both.
    let recipient = IntentRecipient {
        address: w.foreign.address_at(false, 0, 0),
        script_hex: w.foreign.script_at(false, 0, 0).to_hex_string(),
        amount_sat: 20_000,
    };
    let intent = OnchainIntent {
        recipients: vec![recipient.clone(), recipient],
        ..send_btc_intent(&w)
    };
    let two = build_psbt(
        &[InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 20_000, None),
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 20_000, None),
            OutputSpec::new(
                w.ours.script_at(false, 0, 1),
                59_000,
                Some(w.ours.origin(false, 0, 1)),
            ),
        ],
    );
    assert_all_pass(&verify_psbt(&two, &params(&w, intent.clone(), 2_000)));
    let one = build_psbt(
        &[InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 20_000, None),
            OutputSpec::new(
                w.ours.script_at(false, 0, 1),
                79_000,
                Some(w.ours.origin(false, 0, 1)),
            ),
        ],
    );
    let verdict = verify_psbt(&one, &params(&w, intent, 2_000));
    assert_only_fails(&verdict, &[CheckName::RecipientsMatch]);
}

fn witness_intent(amount: Option<u64>) -> OnchainIntent {
    OnchainIntent {
        kind: IntentKind::SendAsset,
        fee_rate_sat_per_vb: 2,
        recipients: vec![],
        asset: Some(IntentAsset {
            asset_id: "rgb:fixture".into(),
            amount: 5,
            recipient_id: "bcrt:wvout:fixture".into(),
            witness_amount_sat: amount,
            transport_endpoints: vec![],
        }),
        utxos: None,
    }
}

#[test]
fn check2_witness_send_requires_exactly_one_foreign_output_of_the_approved_amount() {
    let w = wallets();
    let input = || {
        InputSpec::new(
            w.ours.script_at(true, 0, 0),
            30_000,
            Some(w.ours.origin(true, 0, 0)),
        )
    };
    let change = |amount: u64| {
        OutputSpec::new(
            w.ours.script_at(true, 0, 1),
            amount,
            Some(w.ours.origin(true, 0, 1)),
        )
    };
    let psbt = build_psbt(
        &[input()],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 3), 3_000, None),
            change(26_000),
            OutputSpec::new(opret_script(), 0, None),
        ],
    );
    assert_all_pass(&verify_psbt(
        &psbt,
        &params(&w, witness_intent(Some(3_000)), 2_000),
    ));
    // The same PSBT under a BLIND intent: no foreign output allowed.
    let blind = verify_psbt(&psbt, &params(&w, witness_intent(None), 2_000));
    assert_only_fails(&blind, &[CheckName::ChangeOwn]);

    // Zero candidates: the only foreign output pays the WRONG amount.
    let wrong = build_psbt(
        &[input()],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 3), 2_999, None),
            change(23_000),
        ],
    );
    let verdict = verify_psbt(&wrong, &params(&w, witness_intent(Some(3_000)), 5_000));
    assert!(detail(&verdict, CheckName::RecipientsMatch).contains("found 0"));
    assert_eq!(
        verdict.failed(),
        [CheckName::RecipientsMatch, CheckName::ChangeOwn]
    );

    // Two candidates at the approved amount: ambiguous, must fail.
    let two = build_psbt(
        &[input()],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 3), 3_000, None),
            OutputSpec::new(w.foreign.script_at(false, 0, 4), 3_000, None),
            change(22_000),
        ],
    );
    let verdict = verify_psbt(&two, &params(&w, witness_intent(Some(3_000)), 5_000));
    assert!(detail(&verdict, CheckName::RecipientsMatch).contains("found 2"));
    assert!(!verdict.ok);
}

#[test]
fn check3_unaccounted_foreign_output_fails_only_change_own() {
    let w = wallets();
    // Extra undeclared output skimming 5 000 sat (change reduced to keep the fee).
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                change_amount: 54_000,
                extra_outputs: vec![OutputSpec::new(
                    w.foreign.script_at(false, 0, 2),
                    5_000,
                    None,
                )],
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::ChangeOwn]);
    assert!(detail(&verdict, CheckName::ChangeOwn).contains("output 3 (5000 sat)"));

    // Tampered change: foreign script under our metadata.
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                change_script: Some(w.foreign.script_at(false, 0, 1)),
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::ChangeOwn]);

    // create_utxos: all-own outputs pass; one swapped output is caught.
    let utxos_intent = OnchainIntent {
        kind: IntentKind::CreateUtxos,
        fee_rate_sat_per_vb: 2,
        recipients: vec![],
        asset: None,
        utxos: Some(IntentUtxos {
            up_to: false,
            num: 2,
            size: 1_000,
        }),
    };
    let input = || {
        InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )
    };
    let own = |index: u32, amount: u64| {
        OutputSpec::new(
            w.ours.script_at(false, 0, index),
            amount,
            Some(w.ours.origin(false, 0, index)),
        )
    };
    let good = build_psbt(&[input()], &[own(1, 1_000), own(2, 1_000), own(3, 97_000)]);
    assert_all_pass(&verify_psbt(
        &good,
        &params(&w, utxos_intent.clone(), 2_000),
    ));
    let tampered = build_psbt(
        &[input()],
        &[
            own(1, 1_000),
            own(2, 1_000),
            OutputSpec::new(w.foreign.script_at(false, 0, 3), 97_000, None),
        ],
    );
    assert_only_fails(
        &verify_psbt(&tampered, &params(&w, utxos_intent, 2_000)),
        &[CheckName::ChangeOwn],
    );
}

#[test]
fn check3_own_output_outside_keychain_0_or_index_bound_fails_only_change_own() {
    let w = wallets();
    // The script genuinely re-derives from our xpub at keychain 1, but no
    // descriptor wallet scans keychain 1 — accepting it would let a hostile
    // gateway strand the change where the user can never find it.
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                change_script: Some(w.ours.script_at(false, 1, 0)),
                change_origin: Some(Some(w.ours.origin(false, 1, 0))),
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::ChangeOwn]);

    // Beyond the index bound: index 9e8 is ours yet unrecoverable.
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                change_script: Some(w.ours.script_at(false, 0, 900_000_000)),
                change_origin: Some(Some(w.ours.origin(false, 0, 900_000_000))),
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::ChangeOwn]);

    // The bound is inclusive at the default 10 000 and honours an override.
    let at = |index: u32, max: Option<u32>| {
        let mut p = params(&w, send_btc_intent(&w), 2_000);
        p.max_own_output_index = max;
        verify_psbt(
            &happy_psbt(
                &w,
                Happy {
                    change_script: Some(w.ours.script_at(false, 0, index)),
                    change_origin: Some(Some(w.ours.origin(false, 0, index))),
                    ..Happy::default()
                },
            ),
            &p,
        )
    };
    assert_all_pass(&at(10_000, None));
    assert_only_fails(&at(10_001, None), &[CheckName::ChangeOwn]);
    assert_all_pass(&at(10_001, Some(10_001)));
    assert_only_fails(&at(50, Some(49)), &[CheckName::ChangeOwn]);
    // Metadata-proven change beyond the scan window at a sane index passes.
    assert_all_pass(&at(40, None));
}

#[test]
fn check3_metadata_less_change_uses_the_scan_window_on_demand() {
    let w = wallets();
    let psbt = happy_psbt(
        &w,
        Happy {
            change_origin: Some(None),
            ..Happy::default()
        },
    );
    assert_all_pass(&verify_psbt(&psbt, &params(&w, send_btc_intent(&w), 2_000)));
    let mut no_scan = params(&w, send_btc_intent(&w), 2_000);
    no_scan.change_scan_window = Some(0);
    assert_only_fails(&verify_psbt(&psbt, &no_scan), &[CheckName::ChangeOwn]);
    // Index 1 is inside a window of 2 but outside a window of 1.
    let mut narrow = params(&w, send_btc_intent(&w), 2_000);
    narrow.change_scan_window = Some(2);
    assert_all_pass(&verify_psbt(&psbt, &narrow));
    narrow.change_scan_window = Some(1);
    assert_only_fails(&verify_psbt(&psbt, &narrow), &[CheckName::ChangeOwn]);
    // The scan window covers the colored account too, keychain 0 only.
    let colored_change = build_psbt(
        &[InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 40_000, None),
            OutputSpec::new(w.ours.script_at(true, 0, 29), 59_000, None),
        ],
    );
    assert_all_pass(&verify_psbt(
        &colored_change,
        &params(&w, send_btc_intent(&w), 2_000),
    ));
    let keychain_1 = build_psbt(
        &[InputSpec::new(
            w.ours.script_at(false, 0, 0),
            100_000,
            Some(w.ours.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 40_000, None),
            OutputSpec::new(w.ours.script_at(false, 1, 0), 59_000, None),
        ],
    );
    assert_only_fails(
        &verify_psbt(&keychain_1, &params(&w, send_btc_intent(&w), 2_000)),
        &[CheckName::ChangeOwn],
    );
}

#[test]
fn check4_fee_outside_budget_fails_only_fee_budget() {
    let w = wallets();
    // Inflated: change 20 000 → fee 40 000.
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                change_amount: 20_000,
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::FeeBudget]);
    assert_eq!(verdict.fee_sat, Some(40_000));
    assert!(
        detail(&verdict, CheckName::FeeBudget).contains("fee 40000 sat outside budget (0, 2000]")
    );

    // Zero fee: outputs == inputs.
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                change_amount: 60_000,
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::FeeBudget]);
    assert_eq!(verdict.fee_sat, Some(0));

    // Negative fee: outputs exceed inputs.
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                change_amount: 70_000,
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::FeeBudget]);
    assert_eq!(verdict.fee_sat, Some(-10_000));

    // Budget is inclusive; the fixture PSBT's 1 000 sat fee at budget 1 000
    // passes and at 999 fails.
    let unsigned = fixture_str(
        &w.fixture["signing"]["unsignedPsbt"],
        "signing.unsignedPsbt",
    );
    assert_all_pass(&verify_psbt(
        unsigned,
        &params(&w, send_btc_intent(&w), 1_000),
    ));
    assert_only_fails(
        &verify_psbt(unsigned, &params(&w, send_btc_intent(&w), 999)),
        &[CheckName::FeeBudget],
    );
    assert_only_fails(
        &verify_psbt(unsigned, &params(&w, send_btc_intent(&w), 0)),
        &[CheckName::FeeBudget],
    );
}

#[test]
fn check5_funded_op_return_fails_only_opret_zero() {
    let w = wallets();
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                opret_amount: 500,
                change_amount: 58_500,
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::OpretZero]);
    assert!(detail(&verdict, CheckName::OpretZero).contains("OP_RETURN output 2 carries 500 sat"));
}

#[test]
fn decoy_key_origin_entry_does_not_divert_selection() {
    let w = wallets();
    // A foreign-fingerprint entry on a well-formed own-looking path sits in
    // the same map as ours. Selecting by fingerprint ignores it; selecting by
    // shape would pick whichever sorts first. Both key orders are exercised
    // by using decoys at two different indexes.
    for decoy_index in [1u32, 2, 3, 4] {
        let mut decoy = w.foreign.origin(false, 0, decoy_index);
        decoy.path = w.ours.origin(false, 0, decoy_index).path;
        let psbt = happy_psbt(
            &w,
            Happy {
                input_origins: Some(vec![decoy.clone(), w.ours.origin(false, 0, 0)]),
                input_internal_key: Some(w.ours.xonly_at(false, 0, 0)),
                ..Happy::default()
            },
        );
        let verdict = verify_psbt(&psbt, &params(&w, send_btc_intent(&w), 2_000));
        assert_all_pass(&verdict);

        let parsed: Psbt = psbt.parse().unwrap();
        let origins = &parsed.inputs[0].tap_key_origins;
        assert_eq!(origins.len(), 2);
        let (key, source) = own_derivation(origins, w.ours.fingerprint()).unwrap();
        assert_eq!(key, w.ours.xonly_at(false, 0, 0), "decoy at {decoy_index}");
        assert_eq!(source.1.to_u32_vec(), w.ours.origin(false, 0, 0).path);
        // What verify proved is what sign will derive: the private key for
        // that path is the key behind the selected entry.
        let sk = w
            .ours
            .keys
            .private_key_for_path(&source.1.to_u32_vec())
            .unwrap();
        assert_eq!(sk.x_only_public_key(&Secp256k1::new()).0, key);
    }

    // A decoy on the OUTPUT side must not make foreign change look own either:
    // the entry carries our fingerprint but the script is theirs.
    let mut lying = w.ours.origin(false, 0, 1);
    lying.xonly = w.foreign.xonly_at(false, 0, 1);
    let verdict = verify_psbt(
        &happy_psbt(
            &w,
            Happy {
                change_script: Some(w.foreign.script_at(false, 0, 1)),
                change_origin: Some(Some(lying)),
                ..Happy::default()
            },
        ),
        &params(&w, send_btc_intent(&w), 2_000),
    );
    assert_only_fails(&verdict, &[CheckName::ChangeOwn]);
}

#[test]
fn garbage_and_truncated_psbts_fail_all_five_without_panicking() {
    let w = wallets();
    let p = params(&w, send_btc_intent(&w), 2_000);
    let unsigned = fixture_str(
        &w.fixture["signing"]["unsignedPsbt"],
        "signing.unsignedPsbt",
    );
    let mut cases: Vec<(String, String)> = vec![
        ("not base64".into(), "!!!!not-base64!!!!".into()),
        (
            "random bytes".into(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".into(),
        ),
        ("empty string".into(), String::new()),
        ("truncated psbt magic".into(), "cHNidP8=".into()),
        ("whitespace".into(), "   ".into()),
        ("magic only".into(), "cHNidP8AAA==".into()),
    ];
    // Truncations of the real fixture PSBT at every 4-char base64 boundary.
    for len in (4..unsigned.len()).step_by(4) {
        cases.push((format!("truncated at {len}"), unsigned[..len].to_owned()));
    }
    // Bit flips through the fixture PSBT's bytes.
    let bytes: Psbt = unsigned.parse().unwrap();
    let raw = bytes.serialize();
    for i in (0..raw.len()).step_by(3) {
        let mut flipped = raw.clone();
        flipped[i] ^= 0x55;
        cases.push((format!("bit flip at {i}"), {
            use bitcoin::base64::Engine;
            bitcoin::base64::prelude::BASE64_STANDARD.encode(&flipped)
        }));
    }
    let mnemonic = fixture_mnemonic(&w.fixture);
    let mut unparseable = 0usize;
    for (label, psbt) in cases {
        let verdict = verify_psbt(&psbt, &p);
        assert_eq!(verdict.checks.len(), 5, "{label}");
        assert_no_secret(&format!("{verdict:?}"), &mnemonic, &label);
        if verdict.txid.is_none() {
            // Unparseable: every check fails with the same parse reason.
            unparseable += 1;
            assert!(!verdict.ok, "{label}");
            assert_eq!(verdict.failed(), CheckName::ALL, "{label}: {verdict:?}");
            assert_eq!(verdict.fee_sat, None, "{label}");
            for c in &verdict.checks {
                assert!(
                    c.detail
                        .as_deref()
                        .is_some_and(|d| d.starts_with("psbt could not be safely parsed")),
                    "{label}: {c:?}"
                );
            }
        } else if !label.starts_with("bit flip") {
            panic!("{label} parsed as a PSBT: {verdict:?}");
        }
        // A bit flip that still parses is judged on its merits: a flip in a
        // field no check covers (e.g. the tx version) legitimately passes;
        // a flip in an amount, script or key-origin field fails the check
        // that owns it. What matters here is: no panic, no `Err`, five
        // checks, no secret rendered.
    }
    assert!(
        unparseable > 10,
        "expected most corruptions to be unparseable"
    );

    // Bad xpub material fails all five too, rather than erroring.
    let mut bad_xpubs = params(&w, send_btc_intent(&w), 2_000);
    bad_xpubs.xpubs.fingerprint = "zz".into();
    let verdict = verify_psbt(unsigned, &bad_xpubs);
    assert_eq!(verdict.failed(), CheckName::ALL);
    assert!(detail(&verdict, CheckName::InputsOwn).contains("fingerprint"));
    let mut bad_xpubs = params(&w, send_btc_intent(&w), 2_000);
    bad_xpubs.xpubs.vanilla = "tpubgarbage".into();
    let verdict = verify_psbt(unsigned, &bad_xpubs);
    assert_eq!(verdict.failed(), CheckName::ALL);
    // Wrong network for the xpubs: the fixture's regtest tpubs are not
    // mainnet material, and an intent address of the wrong network fails.
    let mut wrong_net = params(&w, send_btc_intent(&w), 2_000);
    wrong_net.xpubs.network = BitcoinNetwork::Mainnet;
    assert_eq!(verify_psbt(unsigned, &wrong_net).failed(), CheckName::ALL);

    // The foreign wallet's own xpubs see the fixture PSBT as entirely foreign.
    let theirs = VerifyParams {
        intent: send_btc_intent(&w),
        xpubs: w.foreign.keys.xpubs(),
        max_fee_sat: 2_000,
        change_scan_window: None,
        max_own_output_index: None,
    };
    let verdict = verify_psbt(unsigned, &theirs);
    assert_eq!(
        verdict.failed(),
        [CheckName::InputsOwn, CheckName::ChangeOwn]
    );
}

// ---------------------------------------------------------------------------
// Task 5: sign and finalize — txid parity with rgb-lib's own signer,
// signature validity, and refusal on anything verification rejects.
// ---------------------------------------------------------------------------

use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::TapSighashType;
use utexo_minimal_sdk::{verify_and_sign_psbt, SignResult};

fn fixture_unsigned(w: &Wallets) -> &str {
    fixture_str(
        &w.fixture["signing"]["unsignedPsbt"],
        "signing.unsignedPsbt",
    )
}

/// Every check a signed+finalized PSBT must satisfy, independent of which
/// wallet signed it: one 64-byte (SIGHASH_DEFAULT) key-path witness element
/// per input that verifies as BIP-340 over the BIP-341 key-spend sighash
/// against the output key in the spent script, signing metadata dropped,
/// and the transaction extracts to `expected_txid`.
fn assert_signed_and_finalized(signed_psbt: &str, expected_txid: &str) -> Psbt {
    let psbt: Psbt = signed_psbt.parse().expect("signed psbt parses");
    let secp = Secp256k1::new();
    let prevouts: Vec<bitcoin::TxOut> = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("witness_utxo retained"))
        .collect();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (index, input) in psbt.inputs.iter().enumerate() {
        let witness = input
            .final_script_witness
            .as_ref()
            .unwrap_or_else(|| panic!("input {index} not finalized"));
        assert_eq!(witness.len(), 1, "input {index}: key-path witness");
        let sig_bytes = witness.nth(0).unwrap();
        assert_eq!(
            sig_bytes.len(),
            64,
            "input {index}: 64-byte SIGHASH_DEFAULT sig"
        );
        let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes).unwrap();
        let sighash = cache
            .taproot_key_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .unwrap();
        let script = prevouts[index].script_pubkey.as_bytes();
        assert_eq!(&script[..2], &[0x51, 0x20]);
        let output_key = XOnlyPublicKey::from_slice(&script[2..]).unwrap();
        secp.verify_schnorr(
            &signature,
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .unwrap_or_else(|e| panic!("input {index}: signature invalid: {e}"));
        // Finalizer role: signing metadata dropped, UTXO retained.
        assert!(input.tap_key_sig.is_none(), "input {index}");
        assert!(input.tap_key_origins.is_empty(), "input {index}");
        assert!(input.tap_internal_key.is_none(), "input {index}");
        assert!(input.sighash_type.is_none(), "input {index}");
        assert!(input.partial_sigs.is_empty() && input.bip32_derivation.is_empty());
    }
    let tx = psbt.clone().extract_tx().expect("finalized psbt extracts");
    assert_eq!(tx.compute_txid().to_string(), expected_txid);
    psbt
}

#[test]
fn sign_fixture_psbt_matches_rgb_lib_txid_with_a_valid_key_path_signature() {
    let w = wallets();
    let expected_txid = fixture_str(&w.fixture["signing"]["txid"], "signing.txid");
    let result = verify_and_sign_psbt(
        &w.ours.keys,
        fixture_unsigned(&w),
        &params(&w, send_btc_intent(&w), 2_000),
    )
    .expect("fixture PSBT signs");

    // (a) the verdict is ok and is the one signing was conditioned on.
    assert_all_pass(&result.verdict);
    assert_eq!(result.verdict.fee_sat, Some(1_000));
    // (b) txid parity with rgb-lib.
    assert_eq!(result.txid, expected_txid);
    assert_eq!(result.verdict.txid.as_deref(), Some(expected_txid));
    // (c)+(d) exactly one 64-byte witness element that verifies as BIP-340
    // over the BIP-341 sighash against the spent output key ...
    let signed = assert_signed_and_finalized(&result.signed_psbt, expected_txid);
    // ... which is the re-derived x-only key at the fixture input's path
    // (vanilla 0/0), tweaked with no script tree.
    let unsigned: Psbt = fixture_unsigned(&w).parse().unwrap();
    let (entry_key, source) =
        own_derivation(&unsigned.inputs[0].tap_key_origins, w.ours.fingerprint()).unwrap();
    let internal = w.ours.xonly_at(false, 0, 0);
    assert_eq!(entry_key, internal);
    assert_eq!(source.1.to_u32_vec(), w.ours.origin(false, 0, 0).path);
    let (output_key, _) = internal.tap_tweak(&Secp256k1::new(), None);
    let script = &signed.inputs[0]
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey;
    assert_eq!(&script.as_bytes()[2..], &output_key.serialize());

    // (e) rgb-lib's own signed fixture parses to the same txid and has the
    // same witness shape; its bytes are the fixture's recorded signature.
    // Ours are NOT compared byte-for-byte: BIP-340 signatures are randomized.
    let rgb_lib_signed = fixture_str(&w.fixture["signing"]["signedPsbt"], "signing.signedPsbt");
    let theirs = assert_signed_and_finalized(rgb_lib_signed, expected_txid);
    let their_sig = theirs.inputs[0]
        .final_script_witness
        .as_ref()
        .unwrap()
        .nth(0)
        .unwrap();
    assert_eq!(
        their_sig.to_vec(),
        hex_decode(fixture_str(
            &w.fixture["signing"]["witnessSignature"],
            "signing.witnessSignature"
        ))
    );
    let our_sig = signed.inputs[0]
        .final_script_witness
        .as_ref()
        .unwrap()
        .nth(0)
        .unwrap();
    assert_ne!(
        our_sig, their_sig,
        "randomized nonces: byte-equality is not the parity claim"
    );

    // Signing twice gives two different valid signatures for one txid.
    let again = verify_and_sign_psbt(
        &w.ours.keys,
        fixture_unsigned(&w),
        &params(&w, send_btc_intent(&w), 2_000),
    )
    .unwrap();
    assert_eq!(again.txid, result.txid);
    assert_ne!(again.signed_psbt, result.signed_psbt);
    assert_signed_and_finalized(&again.signed_psbt, expected_txid);
}

#[test]
fn sign_handles_multiple_inputs_across_both_accounts() {
    let w = wallets();
    // Own inputs on vanilla 0/3, colored 0/1 and vanilla 1/5 (an odd
    // keychain is fine for inputs), recipient 40 000, own change, OP_RETURN.
    let psbt = build_psbt(
        &[
            InputSpec::new(
                w.ours.script_at(false, 0, 3),
                50_000,
                Some(w.ours.origin(false, 0, 3)),
            ),
            InputSpec::new(
                w.ours.script_at(true, 0, 1),
                30_000,
                Some(w.ours.origin(true, 0, 1)),
            ),
            InputSpec::new(
                w.ours.script_at(false, 1, 5),
                20_000,
                Some(w.ours.origin(false, 1, 5)),
            ),
        ],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 40_000, None),
            OutputSpec::new(
                w.ours.script_at(true, 0, 2),
                59_000,
                Some(w.ours.origin(true, 0, 2)),
            ),
            OutputSpec::new(opret_script(), 0, None),
        ],
    );
    let result = verify_and_sign_psbt(&w.ours.keys, &psbt, &params(&w, send_btc_intent(&w), 2_000))
        .expect("three own inputs sign");
    assert_all_pass(&result.verdict);
    let unsigned: Psbt = psbt.parse().unwrap();
    assert_eq!(result.txid, unsigned.unsigned_tx.compute_txid().to_string());
    let signed = assert_signed_and_finalized(&result.signed_psbt, &result.txid);
    assert_eq!(signed.inputs.len(), 3);
    // Outputs are the finalizer's business only on inputs: their metadata
    // survives for the gateway to read.
    assert_eq!(signed.outputs[1].tap_key_origins.len(), 1);
}

#[test]
fn sign_refuses_tampered_recipient_amount_and_produces_no_signature() {
    let w = wallets();
    let mut tampered = send_btc_intent(&w);
    tampered.recipients[0].amount_sat = 39_000;
    let err = verify_and_sign_psbt(
        &w.ours.keys,
        fixture_unsigned(&w),
        &params(&w, tampered, 2_000),
    )
    .expect_err("tampered amount must be refused");
    let SdkError::VerificationFailed { check, reason } = &err else {
        panic!("expected VerificationFailed, got {err:?}");
    };
    // The failed check names are carried: the first in `check`, all in
    // `reason` (recipients-match, plus change-own on the now-unaccounted
    // foreign output).
    assert_eq!(check, "recipients-match");
    assert!(
        reason.starts_with("refusing to sign: recipients-match ("),
        "{reason}"
    );
    assert!(reason.contains("no output pays 39000 sat"), "{reason}");
    assert!(reason.contains("; change-own ("), "{reason}");
    assert!(!reason.contains("fee-budget"), "{reason}");
    // Nothing was signed: the refusal is an error, not a result, and the
    // only signing entry point is the one that just refused (see
    // `sign_has_exactly_one_entry_point_and_it_verifies_first`).
    assert!(matches!(err, SdkError::VerificationFailed { .. }));

    // Over budget: fee-budget is the (only) failed check.
    let err = verify_and_sign_psbt(
        &w.ours.keys,
        fixture_unsigned(&w),
        &params(&w, send_btc_intent(&w), 500),
    )
    .unwrap_err();
    assert_eq!(
        err,
        SdkError::VerificationFailed {
            check: "fee-budget".into(),
            reason: "refusing to sign: fee-budget (fee 1000 sat outside budget (0, 500])".into(),
        }
    );
}

#[test]
fn sign_refuses_inputs_whose_key_origin_path_is_not_ours() {
    let w = wallets();
    let p = params(&w, send_btc_intent(&w), 2_000);

    // (a) A foreign input (their script, their fingerprint) — the intent
    // matches, but check 1 fails before any signing.
    let mut spec = InputSpec::new(
        w.foreign.script_at(false, 0, 0),
        100_000,
        Some(w.foreign.origin(false, 0, 0)),
    );
    spec.tap_internal_key = Some(w.foreign.xonly_at(false, 0, 0));
    let psbt = build_psbt(
        &[spec],
        &[
            OutputSpec::new(w.foreign.script_at(false, 0, 0), 40_000, None),
            OutputSpec::new(
                w.ours.script_at(false, 0, 1),
                59_000,
                Some(w.ours.origin(false, 0, 1)),
            ),
            OutputSpec::new(opret_script(), 0, None),
        ],
    );
    let err = verify_and_sign_psbt(&w.ours.keys, &psbt, &p).unwrap_err();
    assert!(
        matches!(&err, SdkError::VerificationFailed { check, .. } if check == "inputs-own"),
        "{err:?}"
    );

    // (b) Our fingerprint on a path outside our accounts (account 1').
    let mut odd = w.ours.origin(false, 0, 0);
    odd.path[2] = HARDENED + 1;
    let psbt = happy_psbt(
        &w,
        Happy {
            input_origins: Some(vec![odd]),
            ..Happy::default()
        },
    );
    let err = verify_and_sign_psbt(&w.ours.keys, &psbt, &p).unwrap_err();
    assert!(
        matches!(&err, SdkError::VerificationFailed { check, reason }
            if check == "inputs-own" && reason.contains("not under our accounts")),
        "{err:?}"
    );

    // (c) An input carrying no key-origin entry at all.
    let psbt = happy_psbt(
        &w,
        Happy {
            input_origins: Some(vec![]),
            ..Happy::default()
        },
    );
    let err = verify_and_sign_psbt(&w.ours.keys, &psbt, &p).unwrap_err();
    assert!(
        matches!(&err, SdkError::VerificationFailed { check, .. } if check == "inputs-own"),
        "{err:?}"
    );

    // (d) The verdict belongs to another wallet: the foreign wallet's own
    // PSBT verifies fine against the foreign xpubs, but our keys must not
    // sign on the strength of someone else's verdict.
    let foreign_psbt = build_psbt(
        &[InputSpec::new(
            w.foreign.script_at(false, 0, 0),
            100_000,
            Some(w.foreign.origin(false, 0, 0)),
        )],
        &[
            OutputSpec::new(w.ours.script_at(false, 0, 0), 40_000, None),
            OutputSpec::new(
                w.foreign.script_at(false, 0, 1),
                59_000,
                Some(w.foreign.origin(false, 0, 1)),
            ),
            OutputSpec::new(opret_script(), 0, None),
        ],
    );
    let foreign_intent = OnchainIntent {
        kind: IntentKind::SendBtc,
        fee_rate_sat_per_vb: 2,
        recipients: vec![IntentRecipient {
            address: w.ours.address_at(false, 0, 0),
            script_hex: w.ours.script_at(false, 0, 0).to_hex_string(),
            amount_sat: 40_000,
        }],
        asset: None,
        utxos: None,
    };
    let foreign_params = VerifyParams {
        intent: foreign_intent,
        xpubs: w.foreign.keys.xpubs(),
        max_fee_sat: 2_000,
        change_scan_window: None,
        max_own_output_index: None,
    };
    assert_all_pass(&verify_psbt(&foreign_psbt, &foreign_params));
    let err = verify_and_sign_psbt(&w.ours.keys, &foreign_psbt, &foreign_params).unwrap_err();
    assert_eq!(
        err,
        SdkError::InvalidInput {
            reason: "params.xpubs are not the xpubs of the signing keys".into()
        }
    );
    // The foreign wallet itself signs it.
    let result = verify_and_sign_psbt(&w.foreign.keys, &foreign_psbt, &foreign_params).unwrap();
    assert_signed_and_finalized(&result.signed_psbt, &result.txid);
    // Foreign keys with OUR params: refused up front as a caller bug, before
    // any verdict is even computed.
    let err = verify_and_sign_psbt(&w.foreign.keys, fixture_unsigned(&w), &p).unwrap_err();
    assert!(matches!(&err, SdkError::InvalidInput { .. }), "{err:?}");
    // Foreign keys with THEIR params see our fixture PSBT as foreign input.
    let mut theirs = p.clone();
    theirs.xpubs = w.foreign.keys.xpubs();
    let err = verify_and_sign_psbt(&w.foreign.keys, fixture_unsigned(&w), &theirs).unwrap_err();
    assert!(
        matches!(&err, SdkError::VerificationFailed { check, .. } if check == "inputs-own"),
        "{err:?}"
    );
}

#[test]
fn sign_through_a_decoy_key_origin_entry_ordered_before_ours() {
    let w = wallets();
    // verify selects the entry carrying OUR master fingerprint; sign must
    // use that same entry. Selecting by path shape would pick the decoy (a
    // foreign fingerprint on a well-formed own path) whenever it sorts
    // first, and signing would fail against a key no check covered.
    for decoy_index in [1u32, 2, 3, 4] {
        let mut decoy = w.foreign.origin(false, 0, decoy_index);
        decoy.path = w.ours.origin(false, 0, decoy_index).path;
        let psbt = happy_psbt(
            &w,
            Happy {
                input_origins: Some(vec![decoy, w.ours.origin(false, 0, 0)]),
                input_internal_key: Some(w.ours.xonly_at(false, 0, 0)),
                ..Happy::default()
            },
        );
        let result =
            verify_and_sign_psbt(&w.ours.keys, &psbt, &params(&w, send_btc_intent(&w), 2_000))
                .unwrap_or_else(|e| panic!("decoy at {decoy_index}: {e}"));
        assert_all_pass(&result.verdict);
        assert_signed_and_finalized(&result.signed_psbt, &result.txid);
    }
}

#[test]
fn sign_refuses_sighash_types_that_do_not_commit_to_the_verdict() {
    let w = wallets();
    let p = params(&w, send_btc_intent(&w), 2_000);
    let base: Psbt = fixture_unsigned(&w).parse().unwrap();
    // DEFAULT and ALL commit to every output the verdict approved; both sign.
    for ty in [TapSighashType::Default, TapSighashType::All] {
        let mut psbt = base.clone();
        psbt.inputs[0].sighash_type = Some(ty.into());
        let result = verify_and_sign_psbt(&w.ours.keys, &psbt.to_string(), &p)
            .unwrap_or_else(|e| panic!("{ty}: {e}"));
        let signed: Psbt = result.signed_psbt.parse().unwrap();
        let sig = signed.inputs[0]
            .final_script_witness
            .as_ref()
            .unwrap()
            .nth(0)
            .unwrap();
        // ALL is encoded with a trailing sighash byte (65 bytes), DEFAULT as
        // 64 bytes — both are valid key-path witnesses.
        assert_eq!(
            sig.len(),
            if ty == TapSighashType::Default {
                64
            } else {
                65
            },
            "{ty}"
        );
        assert_eq!(result.txid, base.unsigned_tx.compute_txid().to_string());
    }
    // NONE / SINGLE / ANYONECANPAY variants would let outputs change after
    // approval: refused after verification, with the input index named.
    for ty in [
        TapSighashType::None,
        TapSighashType::Single,
        TapSighashType::AllPlusAnyoneCanPay,
        TapSighashType::NonePlusAnyoneCanPay,
        TapSighashType::SinglePlusAnyoneCanPay,
    ] {
        let mut psbt = base.clone();
        psbt.inputs[0].sighash_type = Some(ty.into());
        let err = verify_and_sign_psbt(&w.ours.keys, &psbt.to_string(), &p).unwrap_err();
        assert!(
            matches!(&err, SdkError::SigningFailed { reason }
                if reason.starts_with("input 0: unsupported sighash type")),
            "{ty}: {err:?}"
        );
    }
    // A raw byte that is no taproot sighash type at all takes the same
    // refusal path (the catch-all arm), not a panic.
    for raw in [4u32, 0x7f, 0x100] {
        let mut psbt = base.clone();
        psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(raw));
        let err = verify_and_sign_psbt(&w.ours.keys, &psbt.to_string(), &p).unwrap_err();
        assert!(
            matches!(&err, SdkError::SigningFailed { reason }
                if reason.starts_with("input 0: unsupported sighash type")),
            "raw {raw:#x}: {err:?}"
        );
    }
}

#[test]
fn sign_errors_never_render_key_material_and_never_panic() {
    let w = wallets();
    let mnemonic = fixture_mnemonic(&w.fixture);
    let p = params(&w, send_btc_intent(&w), 2_000);
    let mut tampered = send_btc_intent(&w);
    tampered.recipients[0].amount_sat = 39_000;
    let unsigned = fixture_unsigned(&w);
    let mut errors: Vec<SdkError> = vec![
        verify_and_sign_psbt(&w.ours.keys, unsigned, &params(&w, tampered, 2_000)).unwrap_err(),
        verify_and_sign_psbt(&w.ours.keys, unsigned, &params(&w, send_btc_intent(&w), 1))
            .unwrap_err(),
        verify_and_sign_psbt(&w.ours.keys, "!!!not a psbt!!!", &p).unwrap_err(),
        verify_and_sign_psbt(&w.ours.keys, "", &p).unwrap_err(),
        verify_and_sign_psbt(&w.ours.keys, "cHNidP8=", &p).unwrap_err(),
    ];
    for len in (4..unsigned.len()).step_by(20) {
        errors.push(verify_and_sign_psbt(&w.ours.keys, &unsigned[..len], &p).unwrap_err());
    }
    for err in &errors {
        // Hostile PSBTs are refused as a failed verdict, never a parse error
        // or panic, so verification stays the single gate.
        assert!(
            matches!(err, SdkError::VerificationFailed { .. }),
            "{err:?}"
        );
    }
    // Mismatched keys/xpubs and unsupported sighash types are the other two
    // error shapes; their messages are fixed diagnostics plus an index.
    errors.push(verify_and_sign_psbt(&w.foreign.keys, unsigned, &p).unwrap_err());
    let mut bad_xpubs = p.clone();
    bad_xpubs.xpubs.fingerprint = "zz".into();
    errors.push(verify_and_sign_psbt(&w.ours.keys, unsigned, &bad_xpubs).unwrap_err());
    let mut none: Psbt = unsigned.parse().unwrap();
    none.inputs[0].sighash_type = Some(TapSighashType::None.into());
    errors.push(verify_and_sign_psbt(&w.ours.keys, &none.to_string(), &p).unwrap_err());
    let other_mnemonic = fixture_str(&w.fixture["otherMnemonic"], "otherMnemonic");
    for err in &errors {
        for m in [mnemonic.as_str(), other_mnemonic] {
            assert_no_secret(&err.to_string(), m, "error display");
            assert_no_secret(&format!("{err:?}"), m, "error debug");
        }
    }
    // A successful result renders no secret either.
    let ok: SignResult = verify_and_sign_psbt(&w.ours.keys, unsigned, &p).unwrap();
    assert_no_secret(&format!("{ok:?}"), &mnemonic, "sign result");
}

#[test]
fn sign_has_exactly_one_entry_point_and_it_verifies_first() {
    // Structural guard for "no exported entry point signs without
    // verifying": the schnorr signing call exists in exactly one place in
    // the library, `src/sign.rs`, whose only `pub fn` is
    // `verify_and_sign_psbt`, and the first thing that function does is run
    // `verify_psbt`. Add a second signing path and this test names it.
    let src = manifest_dir().join("src");
    let mut signing_sites: Vec<(String, usize)> = Vec::new();
    let mut pub_fns_in_sign: Vec<String> = Vec::new();
    for entry in fs::read_dir(&src).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("sign_schnorr") {
                signing_sites.push((name.clone(), n + 1));
            }
            if name == "sign.rs" && code.trim_start().starts_with("pub fn ") {
                pub_fns_in_sign.push(code.trim().to_owned());
            }
        }
    }
    assert_eq!(
        signing_sites.len(),
        1,
        "exactly one schnorr signing site: {signing_sites:?}"
    );
    assert_eq!(signing_sites[0].0, "sign.rs");
    assert_eq!(pub_fns_in_sign, ["pub fn verify_and_sign_psbt("]);
    let sign_rs = fs::read_to_string(src.join("sign.rs")).unwrap();
    let body_start = sign_rs.find("pub fn verify_and_sign_psbt(").unwrap();
    let first_verify = sign_rs[body_start..]
        .find("verify_psbt(psbt_base64, params)")
        .unwrap();
    let first_sign = sign_rs[body_start..].find("sign_schnorr(").unwrap();
    assert!(first_verify < first_sign, "verification precedes signing");
    // No opt-out anywhere in the module's code (comments may name what they
    // rule out).
    let code_only = |text: &str| -> String {
        text.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let sign_code = code_only(&sign_rs);
    for forbidden in ["skip_verify", "unchecked", "force", "unsafe "] {
        assert!(
            !sign_code.contains(forbidden),
            "sign.rs contains {forbidden:?}"
        );
    }
    // The uniffi surface exposes the same single function under the same name.
    let ffi_rs = fs::read_to_string(src.join("ffi.rs")).unwrap();
    let sign_exports: Vec<&str> = ffi_rs
        .lines()
        .filter(|l| l.contains("#[uniffi::export") && l.contains("sign"))
        .collect();
    assert_eq!(
        sign_exports,
        ["#[uniffi::export(name = \"verify_and_sign_psbt\")]"],
        "exactly one signing export, and it verifies"
    );
    // The only things ffi.rs reaches in the sign module are its result type
    // and the verifying entry point: no other signer is exported.
    let ffi_code = code_only(&ffi_rs);
    for (at, _) in ffi_code.match_indices("sign::") {
        let rest = &ffi_code[at + "sign::".len()..];
        assert!(
            rest.starts_with("SignResult") || rest.starts_with("verify_and_sign_psbt("),
            "ffi.rs reaches into sign:: at an unexpected item: {}",
            &rest[..rest.len().min(40)]
        );
    }
}

// ---------------------------------------------------------------------------
// Task 6: invoice decoding — BOLT-11 spec vectors (the reference is
// packages/client-sdk/test/invoice.test.ts) and the real rgb-lib RGB invoice
// from the parity fixture. Every malformed input is `InvoiceDecode`, only.
// ---------------------------------------------------------------------------

use utexo_minimal_sdk::{decode_bolt11, decode_rgb_invoice, BeneficiaryKind};

const SPEC_PAYEE: &str = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad";
const SPEC_HASH: &str = "0001020304050607080900010203040506070809000102030405060708090102";
const SPEC_SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";

const VECTOR_ANY_AMOUNT: &str = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
const VECTOR_COFFEE: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
const VECTOR_UTF8: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr";
const VECTOR_HASHED: &str = "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44";
const VECTOR_TESTNET: &str = "lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8";

fn assert_invoice_decode_error<T: std::fmt::Debug>(result: Result<T, SdkError>, what: &str) {
    match result {
        Err(SdkError::InvoiceDecode { reason }) => {
            assert!(!reason.is_empty(), "{what}: empty reason")
        }
        other => panic!("{what}: expected InvoiceDecode, got {other:?}"),
    }
}

#[test]
fn bolt11_any_amount_donation_vector() {
    let inv = decode_bolt11(VECTOR_ANY_AMOUNT).unwrap();
    assert_eq!(inv.network, BitcoinNetwork::Mainnet);
    assert_eq!(inv.amount_msat, None);
    assert_eq!(inv.payment_hash, SPEC_HASH);
    assert_eq!(inv.payment_secret.as_deref(), Some(SPEC_SECRET));
    assert_eq!(
        inv.description.as_deref(),
        Some("Please consider supporting this project")
    );
    assert_eq!(inv.description_hash, None);
    assert_eq!(inv.payee_node_id, SPEC_PAYEE);
    assert_eq!(inv.timestamp, 1_496_314_658);
    assert_eq!(inv.expiry_seconds, 3600);
}

#[test]
fn bolt11_coffee_vector_amount_and_expiry() {
    let inv = decode_bolt11(VECTOR_COFFEE).unwrap();
    assert_eq!(inv.network, BitcoinNetwork::Mainnet);
    assert_eq!(inv.amount_msat, Some(250_000_000));
    assert_eq!(inv.description.as_deref(), Some("1 cup coffee"));
    assert_eq!(inv.expiry_seconds, 60);
    assert_eq!(inv.payee_node_id, SPEC_PAYEE);
    assert_eq!(inv.payment_hash, SPEC_HASH);
}

#[test]
fn bolt11_utf8_description_vector() {
    let inv = decode_bolt11(VECTOR_UTF8).unwrap();
    assert_eq!(inv.description.as_deref(), Some("ナンセンス 1杯"));
    assert_eq!(inv.amount_msat, Some(250_000_000));
    assert_eq!(inv.payee_node_id, SPEC_PAYEE);
}

#[test]
fn bolt11_hashed_description_vector() {
    let inv = decode_bolt11(VECTOR_HASHED).unwrap();
    assert_eq!(inv.amount_msat, Some(2_000_000_000));
    assert_eq!(inv.description, None);
    assert_eq!(
        inv.description_hash.as_deref(),
        Some("3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1")
    );
    assert_eq!(inv.payee_node_id, SPEC_PAYEE);
}

#[test]
fn bolt11_testnet_vector_ignores_fallback_tag() {
    let inv = decode_bolt11(VECTOR_TESTNET).unwrap();
    assert_eq!(inv.network, BitcoinNetwork::Testnet);
    assert_eq!(inv.amount_msat, Some(2_000_000_000));
    assert_eq!(inv.payee_node_id, SPEC_PAYEE);
    assert_eq!(inv.payment_hash, SPEC_HASH);
}

#[test]
fn bolt11_uppercase_input_decodes_identically() {
    let lower = decode_bolt11(VECTOR_COFFEE).unwrap();
    let upper = decode_bolt11(&VECTOR_COFFEE.to_uppercase()).unwrap();
    assert_eq!(lower, upper);
    // Mixed case is lowercased before decoding, as the TS reference does
    // (`invoice.toLowerCase()`): pasted invoices with a capitalised prefix
    // still decode, and the signature message uses the lowercase HRP.
    let mut mixed = VECTOR_COFFEE.to_owned();
    mixed.replace_range(0..2, "LN");
    assert_eq!(decode_bolt11(&mixed).unwrap(), lower);
}

#[test]
fn bolt11_malformed_inputs_are_invoice_decode_only() {
    // Wrong checksum: flip the last character.
    let last = VECTOR_COFFEE.chars().last().unwrap();
    let corrupted = format!(
        "{}{}",
        &VECTOR_COFFEE[..VECTOR_COFFEE.len() - 1],
        if last == 'h' { 'k' } else { 'h' }
    );
    assert_invoice_decode_error(decode_bolt11(&corrupted), "checksum");
    // Non-lightning bech32 (a segwit address).
    assert_invoice_decode_error(
        decode_bolt11("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
        "segwit address",
    );
    // Truncated data.
    assert_invoice_decode_error(decode_bolt11("lnbc1pvjluez"), "truncated");
    // Not bech32 at all.
    for junk in [
        "",
        "1",
        "lnbc",
        "lnbc1",
        "rgb:~/~/~/x",
        "lnbc1\u{00e9}",
        " lnbc1pvjluez",
    ] {
        assert_invoice_decode_error(decode_bolt11(junk), junk);
    }
}

#[test]
fn bolt11_every_truncation_and_corruption_is_ok_or_invoice_decode() {
    // User-pasted strings: no position may panic or surface any other
    // error variant. Truncations at every length, and one-character
    // corruption at every position, of a real vector.
    let charset: Vec<char> = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".chars().collect();
    let mut decoded_ok = 0usize;
    for vector in [VECTOR_COFFEE, VECTOR_TESTNET] {
        for len in 0..=vector.len() {
            match decode_bolt11(&vector[..len]) {
                Ok(_) => decoded_ok += 1,
                Err(SdkError::InvoiceDecode { .. }) => {}
                Err(other) => panic!("truncation {len}: {other:?}"),
            }
        }
        let chars: Vec<char> = vector.chars().collect();
        for pos in 0..chars.len() {
            let mut mutated = chars.clone();
            let replacement = charset.iter().copied().find(|c| *c != chars[pos]).unwrap();
            mutated[pos] = replacement;
            let s: String = mutated.into_iter().collect();
            match decode_bolt11(&s) {
                Ok(_) => decoded_ok += 1,
                Err(SdkError::InvoiceDecode { .. }) => {}
                Err(other) => panic!("corruption at {pos}: {other:?}"),
            }
        }
    }
    // Only the untruncated originals can decode (2), never a corruption:
    // the checksum catches every single-character change.
    assert_eq!(decoded_ok, 2, "corrupted vectors must not decode");
}

// --- Test-side BOLT-11 encoder: needed to prove the length limit is off and
// --- to exercise the `n` (payee) tag, which none of the spec vectors carries.

fn bytes_to_words(bytes: &[u8]) -> Vec<u8> {
    let mut words = Vec::new();
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = ((acc << 8) | u64::from(b)) & 0xffff_ffff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            words.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        words.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    words
}

fn words_to_bytes_padded(words: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for &w in words {
        acc = ((acc << 5) | u64::from(w)) & 0xffff_ffff;
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

fn tag(tag_type: u8, data: Vec<u8>) -> Vec<u8> {
    // A tag length is 10 bits: at most 1023 words per tagged field.
    assert!(
        data.len() < 1024,
        "tag {tag_type} data too long: {} words",
        data.len()
    );
    let mut out = vec![tag_type, (data.len() / 32) as u8, (data.len() % 32) as u8];
    out.extend(data);
    out
}

/// Encode and sign a BOLT-11 invoice over `hrp` and pre-signature data words.
/// Uses the same checksum engine the library uses, deliberately without the
/// crate's length-limited `encode`.
fn encode_bolt11(hrp: &str, data_words: &[u8], secret: &bitcoin::secp256k1::SecretKey) -> String {
    use bitcoin::bech32::primitives::checksum::{Checksum, Engine, PackedFe32};
    use bitcoin::bech32::{Bech32, Fe32, Hrp};
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::Message;

    let secp = Secp256k1::new();
    let mut message = hrp.as_bytes().to_vec();
    message.extend_from_slice(&words_to_bytes_padded(data_words));
    let digest = Message::from_digest(sha256::Hash::hash(&message).to_byte_array());
    let (recid, compact) = secp
        .sign_ecdsa_recoverable(&digest, secret)
        .serialize_compact();
    let mut sig = compact.to_vec();
    sig.push(recid.to_i32() as u8);
    let mut words = data_words.to_vec();
    words.extend(bytes_to_words(&sig));
    assert_eq!(words.len(), data_words.len() + 104);

    let charset: Vec<char> = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".chars().collect();
    let parsed_hrp = Hrp::parse(hrp).unwrap();
    let mut engine = Engine::<Bech32>::new();
    engine.input_hrp(parsed_hrp);
    for &w in &words {
        engine.input_fe(Fe32::from_char(charset[usize::from(w)]).unwrap());
    }
    engine.input_target_residue();
    let residue = *engine.residue();
    let mut out = format!("{hrp}1");
    for &w in &words {
        out.push(charset[usize::from(w)]);
    }
    for i in 0..Bech32::CHECKSUM_LENGTH {
        out.push(charset[usize::from(residue.unpack(Bech32::CHECKSUM_LENGTH - i - 1))]);
    }
    out
}

fn spec_like_data_words(description: &str, payee_tag: Option<&PublicKey>) -> Vec<u8> {
    let mut data = bytes_to_words(&1_496_314_658u64.to_be_bytes()[3..]); // 5 bytes = 8 words
                                                                         // Timestamp is 7 words (35 bits): drop the leading zero word.
    data.remove(0);
    assert_eq!(data.len(), 7);
    let hash: Vec<u8> = (0..32).map(|i| i as u8).collect();
    data.extend(tag(1, bytes_to_words(&hash)));
    data.extend(tag(16, bytes_to_words(&[0x11; 32])));
    data.extend(tag(13, bytes_to_words(description.as_bytes())));
    if let Some(pk) = payee_tag {
        data.extend(tag(19, bytes_to_words(&pk.serialize())));
    }
    data.extend(tag(6, vec![1, 28])); // expiry 60
    data
}

#[test]
fn bolt11_length_limit_is_disabled_and_payee_recovers() {
    // A 580-byte description plus a 600-word route-hint tag (type 3, which
    // the decoder skips) make the invoice far longer than the 1023-char
    // bech32 code length that the crate's checked decoder enforces; BOLT-11
    // lifts that limit and so must we (route-hinted invoices exceed it).
    let secp = Secp256k1::new();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
    let payee = PublicKey::from_secret_key(&secp, &secret);
    let description: String = "route-hint sized description ".repeat(20);
    assert!(description.len() > 570);
    let mut data = spec_like_data_words(&description, None);
    data.extend(tag(3, (0..600u32).map(|i| (i % 32) as u8).collect()));
    let invoice = encode_bolt11("lnbcrt2500u", &data, &secret);
    assert!(
        invoice.len() > 1023,
        "invoice must exceed the bech32 code length ({} chars)",
        invoice.len()
    );
    let inv = decode_bolt11(&invoice).unwrap();
    assert_eq!(inv.network, BitcoinNetwork::Regtest);
    assert_eq!(inv.amount_msat, Some(250_000_000));
    assert_eq!(inv.payee_node_id, payee.to_string());
    assert_eq!(inv.description.as_deref(), Some(description.as_str()));
    assert_eq!(inv.payment_secret.as_deref(), Some(SPEC_SECRET));
    assert_eq!(inv.timestamp, 1_496_314_658);
    assert_eq!(inv.expiry_seconds, 60);
    // A flipped payload character on the long invoice still fails checksum.
    let mut chars: Vec<char> = invoice.chars().collect();
    let mid = chars.len() / 2;
    chars[mid] = if chars[mid] == 'q' { 'p' } else { 'q' };
    let corrupted: String = chars.into_iter().collect();
    assert_invoice_decode_error(decode_bolt11(&corrupted), "long invoice checksum");
}

#[test]
fn bolt11_payee_tag_is_verified_against_the_signature() {
    let secp = Secp256k1::new();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
    let payee = PublicKey::from_secret_key(&secp, &secret);
    let other = PublicKey::from_secret_key(
        &secp,
        &bitcoin::secp256k1::SecretKey::from_slice(&[10u8; 32]).unwrap(),
    );
    // `n` tag matching the signer: accepted, payee taken from the tag.
    let data = spec_like_data_words("with n tag", Some(&payee));
    let inv = decode_bolt11(&encode_bolt11("lntbs10n", &data, &secret)).unwrap();
    assert_eq!(inv.network, BitcoinNetwork::Signet);
    assert_eq!(inv.amount_msat, Some(1_000));
    assert_eq!(inv.payee_node_id, payee.to_string());
    // `n` tag naming a different key than the signer: refused.
    let data = spec_like_data_words("with wrong n tag", Some(&other));
    assert_invoice_decode_error(
        decode_bolt11(&encode_bolt11("lntbs10n", &data, &secret)),
        "payee tag mismatch",
    );
    // No payment hash at all: refused even though the signature is valid.
    let mut data = bytes_to_words(&1_496_314_658u64.to_be_bytes()[3..]);
    data.remove(0);
    data.extend(tag(13, bytes_to_words(b"no hash")));
    assert_invoice_decode_error(
        decode_bolt11(&encode_bolt11("lnbc", &data, &secret)),
        "missing payment hash",
    );
}

#[test]
fn bolt11_wrong_length_and_duplicate_hash_tags_follow_the_spec() {
    // BOLT-11: a reader MUST skip `p`/`s`/`h` fields of the wrong length and
    // MUST use the first of duplicated known fields.
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[11u8; 32]).unwrap();
    let timestamp = || {
        let mut data = bytes_to_words(&1_496_314_658u64.to_be_bytes()[3..]);
        data.remove(0);
        data
    };
    // A 51-word `p` tag is skipped, which leaves the invoice without a hash.
    let mut data = timestamp();
    data.extend(tag(1, vec![1; 51]));
    data.extend(tag(16, bytes_to_words(&[0x11; 32])));
    data.extend(tag(13, bytes_to_words(b"short hash")));
    assert_invoice_decode_error(
        decode_bolt11(&encode_bolt11("lnbc", &data, &secret)),
        "wrong-length payment hash",
    );
    // A 53-word `p` tag is skipped too; a well-formed one after it is used.
    let hash: Vec<u8> = (0..32).map(|i| i as u8).collect();
    let mut data = timestamp();
    data.extend(tag(1, vec![1; 53]));
    data.extend(tag(1, bytes_to_words(&hash)));
    data.extend(tag(16, bytes_to_words(&[0x11; 32])));
    data.extend(tag(13, bytes_to_words(b"long then good")));
    let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    let inv = decode_bolt11(&encode_bolt11("lnbc", &data, &secret)).unwrap();
    assert_eq!(inv.payment_hash, hash_hex);
    // Two well-formed `p` tags: the first wins, the second is ignored.
    let other: Vec<u8> = (0..32).map(|i| 0xff - i as u8).collect();
    let mut data = timestamp();
    data.extend(tag(1, bytes_to_words(&hash)));
    data.extend(tag(1, bytes_to_words(&other)));
    data.extend(tag(16, bytes_to_words(&[0x11; 32])));
    data.extend(tag(16, bytes_to_words(&[0x22; 32])));
    data.extend(tag(13, bytes_to_words(b"duplicates")));
    let inv = decode_bolt11(&encode_bolt11("lnbc", &data, &secret)).unwrap();
    assert_eq!(inv.payment_hash, hash_hex);
    assert_eq!(inv.payment_secret.as_deref(), Some(SPEC_SECRET));
    // A wrong-length `s` tag leaves the secret absent rather than garbled.
    let mut data = timestamp();
    data.extend(tag(1, bytes_to_words(&hash)));
    data.extend(tag(16, vec![2; 50]));
    data.extend(tag(13, bytes_to_words(b"short secret")));
    let inv = decode_bolt11(&encode_bolt11("lnbc", &data, &secret)).unwrap();
    assert_eq!(inv.payment_secret, None);
}

#[test]
fn rgb_invoice_fixture_witness_receive_matches_rgb_lib() {
    let fixture = load_fixture();
    let wr = &fixture["witnessReceive"];
    let invoice = fixture_str(&wr["invoice"], "witnessReceive.invoice");
    let inv = decode_rgb_invoice(invoice).unwrap();
    assert_eq!(inv.asset_id, None);
    assert_eq!(inv.schema, None);
    assert_eq!(inv.amount, None);
    assert_eq!(inv.assignment_raw, None);
    assert_eq!(
        inv.recipient_id,
        fixture_str(&wr["recipientId"], "witnessReceive.recipientId")
    );
    assert_eq!(inv.beneficiary_kind, BeneficiaryKind::Witness);
    assert_eq!(inv.chain.as_deref(), Some("bcrt"));
    assert_eq!(
        inv.expiry_timestamp,
        Some(
            wr["expirationTimestamp"]
                .as_u64()
                .expect("expirationTimestamp")
        )
    );
    assert_eq!(inv.transport_endpoints, ["rpc://localhost:3000/json-rpc"]);
    assert_eq!(inv.assignment_name, None);
}

#[test]
fn rgb_invoice_blind_with_asset_amount_and_endpoints() {
    let inv = decode_rgb_invoice(
        "rgb:erRCLIhl-nBu1DdF-M8YCRNH-Y3rB0W3-hLZH1DP-1AY9zpQ/RGB20Fixed/100/bcrt:utxob:4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?expiry=1700000000&endpoints=rpc://proxy-a/json-rpc,rpcs://proxy-b/json-rpc",
    )
    .unwrap();
    assert_eq!(
        inv.asset_id.as_deref(),
        Some("rgb:erRCLIhl-nBu1DdF-M8YCRNH-Y3rB0W3-hLZH1DP-1AY9zpQ")
    );
    assert_eq!(inv.schema.as_deref(), Some("RGB20Fixed"));
    assert_eq!(inv.amount, Some(100));
    assert_eq!(inv.beneficiary_kind, BeneficiaryKind::Blind);
    assert_eq!(
        inv.recipient_id,
        "bcrt:utxob:4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa"
    );
    assert_eq!(inv.chain.as_deref(), Some("bcrt"));
    assert_eq!(inv.expiry_timestamp, Some(1_700_000_000));
    assert_eq!(
        inv.transport_endpoints,
        ["rpc://proxy-a/json-rpc", "rpcs://proxy-b/json-rpc"]
    );
}

#[test]
fn rgb_invoice_non_numeric_state_and_assignment_name() {
    let inv = decode_rgb_invoice(
        "rgb:3NoxsLum-cRPebTV-gTZY8qY-KS20lx7-OqgtBls-t7muan4/~/BF/bc:utxob:4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa?assignment_name=assetOwner",
    )
    .unwrap();
    assert_eq!(inv.amount, None);
    assert_eq!(inv.assignment_raw.as_deref(), Some("BF"));
    assert_eq!(inv.assignment_name.as_deref(), Some("assetOwner"));
    assert_eq!(inv.chain.as_deref(), Some("bc"));
    assert_eq!(inv.schema, None);
    assert_eq!(inv.transport_endpoints, Vec::<String>::new());
    assert_eq!(inv.expiry_timestamp, None);
    // Unknown beneficiary grammar passes the id through, kind Unknown.
    let inv = decode_rgb_invoice("rgb:~/~/~/bcrt1qsomething").unwrap();
    assert_eq!(inv.beneficiary_kind, BeneficiaryKind::Unknown);
    assert_eq!(inv.chain, None);
    assert_eq!(inv.recipient_id, "bcrt1qsomething");
    // Percent-encoded endpoints are decoded; empty endpoints dropped.
    let inv =
        decode_rgb_invoice("rgb:~/~/~/bcrt:utxob:x?endpoints=rpc%3A%2F%2Fa%2Fjson-rpc,,").unwrap();
    assert_eq!(inv.transport_endpoints, ["rpc://a/json-rpc"]);
}

#[test]
fn rgb_invoice_malformed_inputs_are_invoice_decode_only() {
    for bad in [
        "rgbx:~/~/~/bcrt:utxob:x",
        "rgb:~/~/bcrt:utxob:x",
        "rgb:~/~/~/",
        "rgb:~/~/~/bcrt:utxob:x?expiry=soon",
        "rgb:~/~/~/bcrt:utxob:x?flag",
        "rgb:~/~/~/~/bcrt:utxob:x",
        "rgb:~/~/99999999999999999999999/bcrt:utxob:x",
        "rgb:~/~/~/bcrt:utxob:x?expiry=99999999999999999999999",
        "",
        "rgb:",
        "lnbc1pvjluez",
    ] {
        assert_invoice_decode_error(decode_rgb_invoice(bad), bad);
    }
    // Every truncation of the fixture invoice is Ok or InvoiceDecode.
    let fixture = load_fixture();
    let invoice = fixture_str(&fixture["witnessReceive"]["invoice"], "invoice");
    for len in 0..=invoice.len() {
        if !invoice.is_char_boundary(len) {
            continue;
        }
        match decode_rgb_invoice(&invoice[..len]) {
            Ok(_) | Err(SdkError::InvoiceDecode { .. }) => {}
            Err(other) => panic!("truncation {len}: {other:?}"),
        }
    }
}

#[test]
fn invoice_decoders_are_exported_and_error_variant_is_named_invoice_decode() {
    let ffi_rs = fs::read_to_string(manifest_dir().join("src/ffi.rs")).unwrap();
    assert!(ffi_rs.contains("#[uniffi::export(name = \"decode_bolt11\")]"));
    assert!(ffi_rs.contains("#[uniffi::export(name = \"decode_rgb_invoice\")]"));
    let lib_rs = fs::read_to_string(manifest_dir().join("src/lib.rs")).unwrap();
    assert!(lib_rs.contains("InvoiceDecode { reason: String }"));
    assert!(!lib_rs.contains("InvalidInvoice"));
    // The invoice module returns no other variant.
    let invoice_rs = fs::read_to_string(manifest_dir().join("src/invoice.rs")).unwrap();
    for variant in [
        "InvalidInput",
        "InvalidPsbt",
        "SigningFailed",
        "Internal {",
        "Transport",
        "Gateway",
        "unwrap()",
        "expect(",
    ] {
        let body = invoice_rs.split("#[cfg(test)]").next().unwrap();
        assert!(!body.contains(variant), "invoice.rs uses {variant}");
    }
}

// ---------------------------------------------------------------------------
// Task 7: gateway client — every route through a fake in-Rust transport (no
// network), intent binding for the three prepare* methods, idempotency keys,
// error mapping and secrets hygiene. The reference is
// packages/client-sdk/test/gateway.test.ts.
// ---------------------------------------------------------------------------

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use utexo_minimal_sdk::gateway::{
    CompleteParams, LnAssetKind, LnDepositPrepareParams, LnInvoiceCreateParams, LnInvoiceState,
    LnPayParams, LnPaymentDirection, LnPaymentStatus, LnWithdrawParams, PrepareCreateUtxosParams,
    PrepareSendAssetParams, PrepareSendBtcParams, ReceiveMode, ReceiveParams, RegisterXpubsParams,
};
use utexo_minimal_sdk::{
    encode_uri_component, generate_idempotency_key, GatewayClient, HttpMethod, HttpRequest,
    HttpResponse, HttpTransport, OperationState,
};

/// Records every request and answers from a queue. Implements the same
/// foreign trait Kotlin/Swift will, so the client is exercised exactly as it
/// is over uniffi, minus the FFI hop.
#[derive(Default)]
struct FakeTransport {
    seen: Mutex<Vec<HttpRequest>>,
    responses: Mutex<VecDeque<Result<HttpResponse, SdkError>>>,
}

impl FakeTransport {
    fn with(responses: Vec<Result<HttpResponse, SdkError>>) -> Arc<Self> {
        Arc::new(FakeTransport {
            seen: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into()),
        })
    }

    fn seen(&self) -> Vec<HttpRequest> {
        self.seen.lock().unwrap().clone()
    }

    fn push(&self, response: Result<HttpResponse, SdkError>) {
        self.responses.lock().unwrap().push_back(response);
    }
}

impl HttpTransport for FakeTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, SdkError> {
        self.seen.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("FakeTransport: no response queued")
    }
}

fn ok(status: u16, body: serde_json::Value) -> Result<HttpResponse, SdkError> {
    Ok(HttpResponse {
        status,
        body: body.to_string(),
    })
}

const UUID_V4_LEN: usize = 36;

fn assert_uuid_v4(key: &str) {
    assert_eq!(key.len(), UUID_V4_LEN, "{key}");
    let parts: Vec<&str> = key.split('-').collect();
    assert_eq!(
        parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
        [8, 4, 4, 4, 12],
        "{key}"
    );
    assert!(
        key.bytes()
            .all(|b| b == b'-' || (b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
        "{key}"
    );
    assert!(parts[2].starts_with('4'), "version nibble: {key}");
    assert!(
        matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'),
        "variant bits: {key}"
    );
}

fn client(transport: &Arc<FakeTransport>, token: Option<&str>) -> GatewayClient {
    GatewayClient::new(
        "http://gw.local",
        token.map(str::to_owned),
        None,
        transport.clone(),
    )
}

fn body_json(request: &HttpRequest) -> serde_json::Value {
    serde_json::from_str(request.body.as_deref().expect("request has a body")).unwrap()
}

fn assert_no_idempotency_key(request: &HttpRequest) {
    assert!(
        !request.headers.contains_key("idempotency-key"),
        "{} carries an idempotency key",
        request.url
    );
}

/// The intent the fake gateway returns for the fixture PSBT: the same
/// 40 000 sat send to the foreign wallet that `send_btc_intent` describes.
fn fixture_send_btc_intent_json(w: &Wallets) -> serde_json::Value {
    serde_json::json!({
        "kind": "send_btc",
        "feeRateSatPerVb": 2,
        "recipients": [{
            "address": w.foreign.address_at(false, 0, 0),
            "scriptHex": w.foreign.script_at(false, 0, 0).to_hex_string(),
            "amountSat": 40_000
        }],
        "asset": null,
        "utxos": null
    })
}

fn prepared(intent: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "opId": "op-1", "psbt": "cHNidP8=", "expiresAt": 1, "intent": intent })
}

const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const ATTACKER: &str = "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

fn send_btc_intent_json() -> serde_json::Value {
    serde_json::json!({
        "kind": "send_btc",
        "feeRateSatPerVb": 2,
        "recipients": [{ "address": ADDRESS, "scriptHex": "0014deadbeef", "amountSat": 40_000 }],
        "asset": null,
        "utxos": null
    })
}

fn send_asset_intent_json() -> serde_json::Value {
    serde_json::json!({
        "kind": "send_asset",
        "feeRateSatPerVb": 2,
        "recipients": [],
        "asset": {
            "assetId": "rgb:good",
            "amount": 10,
            "recipientId": "utxob:me",
            "witnessAmountSat": null,
            "transportEndpoints": ["http://proxy"]
        },
        "utxos": null
    })
}

fn create_utxos_intent_json() -> serde_json::Value {
    serde_json::json!({
        "kind": "create_utxos",
        "feeRateSatPerVb": 2,
        "recipients": [],
        "asset": null,
        "utxos": { "upTo": false, "num": 4, "size": 1_000 }
    })
}

fn send_btc_params() -> PrepareSendBtcParams {
    PrepareSendBtcParams {
        address: ADDRESS.into(),
        amount_sat: 40_000,
        fee_rate_sat_per_vb: None,
    }
}

fn send_asset_params() -> PrepareSendAssetParams {
    PrepareSendAssetParams {
        asset_id: "rgb:good".into(),
        amount: 10,
        recipient_id: "utxob:me".into(),
        witness_amount_sat: None,
        transport_endpoints: None,
        donation: None,
        min_confirmations: None,
        fee_rate_sat_per_vb: None,
    }
}

fn assert_intent_mismatch<T: std::fmt::Debug>(
    result: Result<T, SdkError>,
    expected_detail: &str,
    what: &str,
) {
    match result {
        Err(SdkError::IntentMismatch { reason }) => assert!(
            reason.contains(expected_detail),
            "{what}: mismatch reason {reason:?} does not mention {expected_detail:?}"
        ),
        other => panic!("{what}: expected IntentMismatch, got {other:?}"),
    }
}

#[test]
fn gateway_every_route_round_trips_with_method_path_auth_and_body_shape() {
    let hash = "c".repeat(64);
    let transport = FakeTransport::with(vec![
        ok(200, serde_json::json!({ "userId": "u1", "createdAt": 7 })),
        ok(
            200,
            serde_json::json!({ "fingerprint": "73c5da0a", "address": "bcrt1p...a" }),
        ),
        ok(200, serde_json::json!({ "address": "bcrt1p...b" })),
        ok(
            200,
            serde_json::json!({
                "btc": {
                    "vanilla": { "settled": 1, "future": 2, "spendable": 3 },
                    "colored": { "settled": 4, "future": 5, "spendable": 6 }
                },
                "assets": [{
                    "assetId": "rgb:x", "schema": "NIA", "ticker": null, "name": "X",
                    "precision": 8, "balance": { "settled": 7, "future": 8, "spendable": 9 }
                }]
            }),
        ),
        ok(
            200,
            serde_json::json!({ "unspents": [{
                "txid": "aa", "vout": 1, "amountSat": 1000, "colorable": true,
                "allocations": [{ "assetId": "rgb:x", "amount": 5, "settled": true },
                                { "assetId": null, "amount": null, "settled": false }]
            }] }),
        ),
        ok(
            200,
            serde_json::json!({ "transfers": [{
                "idx": 3, "assetId": "rgb:x", "amount": 5, "kind": "issuance", "status": "settled",
                "txid": null, "recipientId": null, "expiration": null, "createdAt": 1, "updatedAt": 2
            }] }),
        ),
        ok(200, serde_json::json!({ "transfers": [] })),
        ok(
            201,
            serde_json::json!({
                "invoice": "rgb:~/~/~/bcrt:utxob:x", "recipientId": "bcrt:utxob:x",
                "expirationTimestamp": 99, "mode": "blind"
            }),
        ),
        ok(200, serde_json::json!({ "status": "ok" })),
        ok(200, prepared(send_btc_intent_json())),
        ok(200, serde_json::json!({ "txid": "bb" })),
        ok(200, prepared(send_asset_intent_json())),
        ok(200, serde_json::json!({ "txid": "cc" })),
        ok(200, prepared(create_utxos_intent_json())),
        ok(200, serde_json::json!({ "txid": null, "utxosCreated": 4 })),
        ok(
            201,
            serde_json::json!({
                "depositId": "d", "kind": "btc", "address": "bcrt1q...", "invoice": null,
                "recipientId": null
            }),
        ),
        ok(
            200,
            serde_json::json!({ "paymentHash": hash, "status": "pending" }),
        ),
        ok(
            201,
            serde_json::json!({ "invoice": "lnbcrt1...", "paymentHash": hash }),
        ),
        ok(
            200,
            serde_json::json!({
                "paymentHash": hash, "invoice": "lnbcrt1...", "state": "pending",
                "amtMsat": 1000, "assetId": null, "assetAmount": null, "createdAt": 1
            }),
        ),
        ok(
            200,
            serde_json::json!({ "payments": [{
                "paymentHash": hash, "direction": "outbound", "status": "succeeded",
                "amtMsat": 1000, "assetId": null, "assetAmount": null, "createdAt": 1,
                "updatedAt": 2
            }] }),
        ),
        ok(
            200,
            serde_json::json!({ "btcMsat": 5000, "assets": { "rgb:x": 12 } }),
        ),
        ok(
            201,
            serde_json::json!({ "withdrawalId": "w", "txid": "dd" }),
        ),
    ]);
    let c = client(&transport, Some("tok-1"));

    assert_eq!(c.me().unwrap().user_id, "u1");
    let registered = c
        .register_xpubs(&RegisterXpubsParams {
            vanilla: "tpubV".into(),
            colored: "tpubC".into(),
            fingerprint: "73c5da0a".into(),
        })
        .unwrap();
    assert_eq!(registered.address, "bcrt1p...a");
    assert_eq!(c.get_address().unwrap().address, "bcrt1p...b");
    let balances = c.get_balances().unwrap();
    assert_eq!(balances.btc.colored.spendable, 6);
    assert_eq!(balances.assets[0].ticker, None);
    assert_eq!(balances.assets[0].balance.settled, 7);
    let unspents = c.get_unspents().unwrap();
    assert_eq!(unspents.unspents[0].allocations[0].amount, Some(5));
    assert_eq!(unspents.unspents[0].allocations[1].asset_id, None);
    let transfers = c.get_transfers(Some("rgb:abc-123")).unwrap();
    assert_eq!(transfers.transfers[0].idx, 3);
    assert!(c.get_transfers(None).unwrap().transfers.is_empty());
    let received = c
        .receive(&ReceiveParams {
            mode: ReceiveMode::Blind,
            asset_id: Some("rgb:x".into()),
            amount: Some(5),
            duration_seconds: None,
            min_confirmations: Some(1),
        })
        .unwrap();
    assert_eq!(received.mode, ReceiveMode::Blind);
    assert_eq!(received.expiration_timestamp, Some(99));
    assert_eq!(c.sync().unwrap().status, "ok");
    let op = c.prepare_send_btc(&send_btc_params(), None).unwrap();
    assert_eq!(op.op_id, "op-1");
    assert_eq!(op.intent.kind, IntentKind::SendBtc);
    let complete = CompleteParams {
        op_id: "op-1".into(),
        signed_psbt: "cHNidP8=".into(),
    };
    assert_eq!(c.complete_send_btc(&complete, None).unwrap().txid, "bb");
    let op = c.prepare_send_asset(&send_asset_params(), None).unwrap();
    assert_eq!(op.intent.asset.as_ref().unwrap().asset_id, "rgb:good");
    assert_eq!(c.complete_send_asset(&complete, None).unwrap().txid, "cc");
    let op = c
        .prepare_create_utxos(
            &PrepareCreateUtxosParams {
                num: Some(4),
                size: None,
                up_to: None,
                fee_rate_sat_per_vb: None,
            },
            None,
        )
        .unwrap();
    assert_eq!(op.intent.utxos.as_ref().unwrap().num, 4);
    let created = c.complete_create_utxos(&complete, None).unwrap();
    assert_eq!((created.txid, created.utxos_created), (None, 4));
    let deposit = c
        .prepare_ln_deposit(
            &LnDepositPrepareParams {
                kind: LnAssetKind::Btc,
                amount_msat: Some(1_000_000),
                asset_id: None,
                amount: None,
            },
            None,
        )
        .unwrap();
    assert_eq!(deposit.address.as_deref(), Some("bcrt1q..."));
    assert_eq!(deposit.kind, LnAssetKind::Btc);
    let paid = c
        .pay_ln_invoice(
            &LnPayParams {
                invoice: "lnbcrt1...".into(),
                amt_msat: None,
                asset_amount: None,
            },
            None,
        )
        .unwrap();
    assert_eq!(paid.status, LnPaymentStatus::Pending);
    let invoice = c
        .create_ln_invoice(&LnInvoiceCreateParams {
            amt_msat: Some(1000),
            expiry_sec: None,
            asset_id: None,
            asset_amount: None,
            description: Some("coffee".into()),
        })
        .unwrap();
    assert_eq!(invoice.payment_hash, hash);
    let info = c.get_ln_invoice("../v1/ln/balance").unwrap();
    assert_eq!(info.state, LnInvoiceState::Pending);
    let payments = c.list_ln_payments().unwrap();
    assert_eq!(payments.payments[0].direction, LnPaymentDirection::Outbound);
    assert_eq!(payments.payments[0].status, LnPaymentStatus::Succeeded);
    let ln_balance = c.get_ln_balance().unwrap();
    assert_eq!(ln_balance.btc_msat, 5000);
    assert_eq!(ln_balance.assets.get("rgb:x"), Some(&12));
    let withdrawn = c
        .withdraw_ln(
            &LnWithdrawParams {
                kind: LnAssetKind::Btc,
                address: Some("bcrt1q...".into()),
                amount_sat: Some(1_000),
                asset_id: None,
                amount: None,
                recipient_id: None,
                witness_amount_sat: None,
                transport_endpoints: None,
                fee_rate_sat_per_vb: None,
            },
            None,
        )
        .unwrap();
    assert_eq!(withdrawn.txid, "dd");

    // Method, path, auth header and body shape, in call order.
    let seen = transport.seen();
    let expected: Vec<(HttpMethod, &str, Option<serde_json::Value>, bool)> = vec![
        (HttpMethod::Get, "/v1/me", None, false),
        (
            HttpMethod::Post,
            "/v1/wallet/xpubs",
            Some(
                serde_json::json!({ "vanilla": "tpubV", "colored": "tpubC", "fingerprint": "73c5da0a" }),
            ),
            false,
        ),
        (HttpMethod::Get, "/v1/wallet/address", None, false),
        (HttpMethod::Get, "/v1/wallet/balances", None, false),
        (HttpMethod::Get, "/v1/wallet/unspents", None, false),
        (
            HttpMethod::Get,
            "/v1/wallet/transfers?assetId=rgb%3Aabc-123",
            None,
            false,
        ),
        (HttpMethod::Get, "/v1/wallet/transfers", None, false),
        (
            HttpMethod::Post,
            "/v1/wallet/receive",
            Some(
                serde_json::json!({ "mode": "blind", "assetId": "rgb:x", "amount": 5, "minConfirmations": 1 }),
            ),
            false,
        ),
        (HttpMethod::Post, "/v1/wallet/sync", None, false),
        (
            HttpMethod::Post,
            "/v1/onchain/send-btc/prepare",
            Some(serde_json::json!({ "address": ADDRESS, "amountSat": 40_000 })),
            true,
        ),
        (
            HttpMethod::Post,
            "/v1/onchain/send-btc/complete",
            Some(serde_json::json!({ "opId": "op-1", "signedPsbt": "cHNidP8=" })),
            true,
        ),
        (
            HttpMethod::Post,
            "/v1/onchain/send-asset/prepare",
            Some(
                serde_json::json!({ "assetId": "rgb:good", "amount": 10, "recipientId": "utxob:me" }),
            ),
            true,
        ),
        (
            HttpMethod::Post,
            "/v1/onchain/send-asset/complete",
            Some(serde_json::json!({ "opId": "op-1", "signedPsbt": "cHNidP8=" })),
            true,
        ),
        (
            HttpMethod::Post,
            "/v1/onchain/create-utxos/prepare",
            Some(serde_json::json!({ "num": 4 })),
            true,
        ),
        (
            HttpMethod::Post,
            "/v1/onchain/create-utxos/complete",
            Some(serde_json::json!({ "opId": "op-1", "signedPsbt": "cHNidP8=" })),
            true,
        ),
        (
            HttpMethod::Post,
            "/v1/ln/deposit/prepare",
            Some(serde_json::json!({ "kind": "btc", "amountMsat": 1_000_000 })),
            true,
        ),
        (
            HttpMethod::Post,
            "/v1/ln/pay",
            Some(serde_json::json!({ "invoice": "lnbcrt1..." })),
            true,
        ),
        (
            HttpMethod::Post,
            "/v1/ln/invoice",
            Some(serde_json::json!({ "amtMsat": 1000, "description": "coffee" })),
            false,
        ),
        (
            HttpMethod::Get,
            "/v1/ln/invoice/..%2Fv1%2Fln%2Fbalance",
            None,
            false,
        ),
        (HttpMethod::Get, "/v1/ln/payments", None, false),
        (HttpMethod::Get, "/v1/ln/balance", None, false),
        (
            HttpMethod::Post,
            "/v1/ln/withdraw",
            Some(serde_json::json!({ "kind": "btc", "address": "bcrt1q...", "amountSat": 1_000 })),
            true,
        ),
    ];
    assert_eq!(seen.len(), expected.len(), "one request per route");
    for (request, (method, path, body, money_moving)) in seen.iter().zip(expected) {
        assert_eq!(request.method, method, "{path}");
        assert_eq!(request.url, format!("http://gw.local{path}"));
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer tok-1"),
            "{path}"
        );
        assert_eq!(request.timeout_ms, 30_000);
        match body {
            Some(expected_body) => {
                assert_eq!(body_json(request), expected_body, "{path} body");
                assert_eq!(
                    request.headers.get("content-type").map(String::as_str),
                    Some("application/json"),
                    "{path}"
                );
            }
            None => {
                assert_eq!(request.body, None, "{path} must carry no body");
                assert!(!request.headers.contains_key("content-type"), "{path}");
            }
        }
        if money_moving {
            assert_uuid_v4(request.headers.get("idempotency-key").expect(path));
        } else {
            assert_no_idempotency_key(request);
        }
    }
    // 22 distinct routes were covered (transfers and invoice/{hash} twice).
    let routes: std::collections::BTreeSet<&str> = seen
        .iter()
        .map(|r| {
            r.url
                .trim_start_matches("http://gw.local")
                .split('?')
                .next()
                .unwrap()
        })
        .map(|p| {
            if p.starts_with("/v1/ln/invoice/") {
                "/v1/ln/invoice/{hash}"
            } else {
                p
            }
        })
        .collect();
    assert_eq!(routes.len(), 21);
    // create_user is the 22nd: operator token, no bearer, no body.
    let transport = FakeTransport::with(vec![ok(
        201,
        serde_json::json!({ "userId": "u1", "token": "t-new", "createdAt": 1 }),
    )]);
    let created = client(&transport, None).create_user("op-secret").unwrap();
    assert_eq!(created.token, "t-new");
    let request = &transport.seen()[0];
    assert_eq!(request.method, HttpMethod::Post);
    assert_eq!(request.url, "http://gw.local/v1/users");
    assert_eq!(
        request.headers.get("x-operator-token").map(String::as_str),
        Some("op-secret")
    );
    assert!(!request.headers.contains_key("authorization"));
    assert_eq!(request.body, None);
    assert_no_idempotency_key(request);
}

#[test]
fn gateway_get_onchain_operation_reads_durable_state_after_a_lost_complete() {
    let op_id = "11111111-2222-4333-8444-555555555555";
    let status_json = |state: &str, txid: serde_json::Value, may: bool| {
        serde_json::json!({
            "opId": op_id,
            "kind": "send_btc",
            "state": state,
            "txid": txid,
            "mayHaveBroadcast": may,
            "intent": send_btc_intent_json(),
            "createdAt": 1_700_000_000_000u64,
            "expiresAt": 1_700_000_900_000u64,
        })
    };
    let transport = FakeTransport::with(vec![
        ok(200, status_json("pending", serde_json::Value::Null, false)),
        // The case this route exists for: the wallet failed after rgb-lib may
        // already have broadcast, so a txid is recorded on an op that never
        // completed.
        ok(
            200,
            status_json("pending", serde_json::json!("d".repeat(64)), true),
        ),
        // Expiry must not clear the signal: an expired op whose txid was
        // recorded may still have its transaction confirmed.
        ok(
            200,
            status_json("expired", serde_json::json!("d".repeat(64)), true),
        ),
        ok(
            200,
            status_json("completed", serde_json::json!("e".repeat(64)), false),
        ),
    ]);
    let c = client(&transport, Some("tok-1"));

    let fresh = c.get_onchain_operation(op_id).unwrap();
    assert_eq!(fresh.op_id, op_id);
    assert_eq!(fresh.kind, IntentKind::SendBtc);
    assert_eq!(fresh.state, OperationState::Pending);
    assert_eq!(fresh.txid, None);
    assert!(!fresh.may_have_broadcast);
    // The intent comes back through the same typed decoder `prepare` uses.
    assert_eq!(fresh.intent.kind, IntentKind::SendBtc);
    assert_eq!(fresh.intent.recipients[0].amount_sat, 40_000);
    assert_eq!(fresh.created_at, 1_700_000_000_000);
    assert_eq!(fresh.expires_at, 1_700_000_900_000);

    let ambiguous = c.get_onchain_operation(op_id).unwrap();
    assert_eq!(ambiguous.state, OperationState::Pending);
    assert!(ambiguous.may_have_broadcast);
    assert_eq!(ambiguous.txid, Some("d".repeat(64)));

    let expired = c.get_onchain_operation(op_id).unwrap();
    assert_eq!(expired.state, OperationState::Expired);
    assert!(expired.may_have_broadcast, "expiry does not un-broadcast");

    let done = c.get_onchain_operation(op_id).unwrap();
    assert_eq!(done.state, OperationState::Completed);
    assert!(!done.may_have_broadcast);

    // A read: GET, percent-encoded path, bearer auth, no body, and no
    // idempotency key — so polling it can never consume one.
    for request in transport.seen() {
        assert_eq!(request.method, HttpMethod::Get);
        assert_eq!(
            request.url,
            format!("http://gw.local/v1/onchain/operations/{op_id}")
        );
        assert_eq!(request.body, None);
        assert_no_idempotency_key(&request);
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer tok-1")
        );
    }
}

#[test]
fn gateway_get_onchain_operation_fails_closed_on_unknown_state_or_kind() {
    let base = |state: &str, kind: &str| {
        serde_json::json!({
            "opId": "11111111-2222-4333-8444-555555555555",
            "kind": kind,
            "state": state,
            "txid": null,
            "mayHaveBroadcast": false,
            "intent": send_btc_intent_json(),
            "createdAt": 1u64,
            "expiresAt": 2u64,
        })
    };
    // A state or kind this SDK does not know must be an error, never a silent
    // default — the caller decides recovery on these fields.
    let mut missing_flag = base("pending", "send_btc");
    missing_flag["mayHaveBroadcast"] = serde_json::Value::Null;
    let transport = FakeTransport::with(vec![
        ok(200, base("teleported", "send_btc")),
        ok(200, base("pending", "send_dogecoin")),
        ok(200, missing_flag),
    ]);
    let c = client(&transport, Some("tok-1"));
    for _ in 0..3 {
        assert!(matches!(
            c.get_onchain_operation("11111111-2222-4333-8444-555555555555"),
            Err(SdkError::Gateway { .. })
        ));
    }
}

#[test]
fn gateway_base_url_trailing_slash_percent_encoding_and_no_token_guard() {
    let transport = FakeTransport::with(vec![ok(200, serde_json::json!({ "address": "x" }))]);
    let c = GatewayClient::new(
        "http://gw.local///",
        Some("tok-1".into()),
        Some(5),
        transport.clone(),
    );
    c.get_address().unwrap();
    let request = &transport.seen()[0];
    assert_eq!(request.url, "http://gw.local/v1/wallet/address");
    assert_eq!(request.timeout_ms, 5);
    assert_eq!(encode_uri_component("rgb:abc-123"), "rgb%3Aabc-123");

    // Authenticated calls without a token fail before any network IO.
    let transport = FakeTransport::with(vec![]);
    let c = client(&transport, None);
    match c.get_balances() {
        Err(SdkError::Gateway { status, code, .. }) => {
            assert_eq!((status, code.as_str()), (0, "NO_TOKEN"));
        }
        other => panic!("expected NO_TOKEN, got {other:?}"),
    }
    assert!(transport.seen().is_empty(), "no request may be sent");
}

#[test]
fn gateway_status_and_body_surface_on_4xx_and_5xx() {
    let transport = FakeTransport::with(vec![
        ok(
            409,
            serde_json::json!({ "error": { "code": "IDEMPOTENCY_CONFLICT", "message": "key reused" } }),
        ),
        Ok(HttpResponse {
            status: 502,
            body: "<html>bad gateway</html>".into(),
        }),
        Ok(HttpResponse {
            status: 500,
            body: String::new(),
        }),
        ok(400, serde_json::json!({ "error": { "code": 5 } })),
        Err(SdkError::Transport {
            reason: "connection refused".into(),
        }),
        // A 2xx that is not the documented shape is an explicit error, not a
        // default value.
        ok(200, serde_json::json!({ "address": 5 })),
        Ok(HttpResponse {
            status: 200,
            body: "not json".into(),
        }),
    ]);
    let c = client(&transport, Some("tok-1"));
    assert_eq!(
        c.sync().unwrap_err(),
        SdkError::Gateway {
            status: 409,
            code: "IDEMPOTENCY_CONFLICT".into(),
            detail: "key reused".into()
        }
    );
    assert_eq!(
        c.me().unwrap_err(),
        SdkError::Gateway {
            status: 502,
            code: "UNKNOWN".into(),
            detail: "gateway returned 502".into()
        }
    );
    assert_eq!(
        c.me().unwrap_err(),
        SdkError::Gateway {
            status: 500,
            code: "UNKNOWN".into(),
            detail: "gateway returned 500".into()
        }
    );
    assert_eq!(
        c.me().unwrap_err(),
        SdkError::Gateway {
            status: 400,
            code: "UNKNOWN".into(),
            detail: "gateway returned 400".into()
        }
    );
    assert_eq!(
        c.me().unwrap_err(),
        SdkError::Transport {
            reason: "connection refused".into()
        }
    );
    // Any declared error variant the transport returns is passed through
    // untouched, not re-wrapped as Transport.
    let foreign = SdkError::Gateway {
        status: 0,
        code: "HOST_CANCELLED".into(),
        detail: "the app cancelled the request".into(),
    };
    let cancelled = FakeTransport::with(vec![Err(foreign.clone())]);
    assert_eq!(client(&cancelled, Some("tok-1")).me().unwrap_err(), foreign);
    for what in ["wrong type", "non-json"] {
        match c.get_address() {
            Err(SdkError::Gateway {
                status,
                code,
                detail,
            }) => {
                assert_eq!((status, code.as_str()), (0, "MALFORMED_RESPONSE"), "{what}");
                assert!(detail.contains("address"), "{what}: {detail}");
            }
            other => panic!("{what}: expected MALFORMED_RESPONSE, got {other:?}"),
        }
    }
    // Unknown enum values on the wire are refused rather than mapped.
    transport.push(ok(
        200,
        serde_json::json!({ "paymentHash": "a", "status": "maybe" }),
    ));
    let err = c
        .pay_ln_invoice(
            &LnPayParams {
                invoice: "x".into(),
                amt_msat: None,
                asset_amount: None,
            },
            None,
        )
        .unwrap_err();
    assert!(
        matches!(err, SdkError::Gateway { ref code, .. } if code == "MALFORMED_RESPONSE"),
        "{err:?}"
    );
}

#[test]
fn gateway_idempotency_keys_are_unique_per_call_and_stable_when_pinned() {
    let mut keys = std::collections::HashSet::new();
    for _ in 0..64 {
        let key = generate_idempotency_key().unwrap();
        assert_uuid_v4(&key);
        assert!(keys.insert(key), "duplicate idempotency key");
    }

    let transport = FakeTransport::with(vec![
        ok(200, prepared(send_btc_intent_json())),
        ok(200, prepared(create_utxos_intent_json())),
        ok(200, serde_json::json!({ "txid": "aa" })),
        ok(200, serde_json::json!({ "txid": "aa" })),
        ok(
            200,
            serde_json::json!({ "paymentHash": "a", "status": "pending" }),
        ),
        ok(200, serde_json::json!({ "withdrawalId": "w", "txid": "b" })),
        ok(200, serde_json::json!({ "btcMsat": 0, "assets": {} })),
        ok(200, serde_json::json!({ "payments": [] })),
    ]);
    let c = client(&transport, Some("t"));
    c.prepare_send_btc(&send_btc_params(), None).unwrap();
    c.prepare_create_utxos(
        &PrepareCreateUtxosParams {
            num: None,
            size: None,
            up_to: None,
            fee_rate_sat_per_vb: None,
        },
        None,
    )
    .unwrap();
    let pinned = generate_idempotency_key().unwrap();
    let complete = CompleteParams {
        op_id: "op".into(),
        signed_psbt: "cHNidP8=".into(),
    };
    c.complete_send_btc(&complete, Some(pinned.clone()))
        .unwrap();
    c.complete_send_btc(&complete, Some(pinned.clone()))
        .unwrap();
    c.pay_ln_invoice(
        &LnPayParams {
            invoice: "lnbcrt1...".into(),
            amt_msat: None,
            asset_amount: None,
        },
        Some(pinned.clone()),
    )
    .unwrap();
    c.withdraw_ln(
        &LnWithdrawParams {
            kind: LnAssetKind::Btc,
            address: Some("bcrt1q...".into()),
            amount_sat: Some(1_000),
            asset_id: None,
            amount: None,
            recipient_id: None,
            witness_amount_sat: None,
            transport_endpoints: None,
            fee_rate_sat_per_vb: None,
        },
        None,
    )
    .unwrap();
    c.get_ln_balance().unwrap();
    c.list_ln_payments().unwrap();

    let seen = transport.seen();
    let key = |i: usize| seen[i].headers.get("idempotency-key").cloned();
    assert_uuid_v4(&key(0).unwrap());
    assert_uuid_v4(&key(1).unwrap());
    assert_ne!(key(0), key(1), "fresh key per money-moving call");
    assert_eq!(key(2).as_deref(), Some(pinned.as_str()));
    assert_eq!(key(3).as_deref(), Some(pinned.as_str()));
    assert_eq!(key(4).as_deref(), Some(pinned.as_str()));
    assert_uuid_v4(&key(5).unwrap());
    assert_eq!(key(6), None, "reads carry no idempotency key");
    assert_eq!(key(7), None);
}

#[test]
fn intent_binding_send_btc_rejects_every_tampered_field_and_accepts_a_match() {
    // verify check 2 matches the PSBT against the intent. A server-echoed
    // intent makes that check vacuous against a hostile gateway: it can put
    // an attacker output in the PSBT and the SAME attacker output in the
    // intent, and every one of the 5 checks passes. These bind the intent to
    // what the caller actually asked for, before it can reach verify_psbt.
    let run = |intent: serde_json::Value, params: &PrepareSendBtcParams| {
        let transport = FakeTransport::with(vec![ok(200, prepared(intent))]);
        client(&transport, Some("t")).prepare_send_btc(params, None)
    };
    let with = |patch: serde_json::Value| {
        let mut intent = send_btc_intent_json();
        for (k, v) in patch.as_object().unwrap() {
            intent[k] = v.clone();
        }
        intent
    };

    let op = run(send_btc_intent_json(), &send_btc_params()).unwrap();
    assert_eq!(op.op_id, "op-1");
    assert_eq!(op.psbt, "cHNidP8=");
    assert_eq!(op.expires_at, 1);
    // Server-chosen defaults are left alone: feeRateSatPerVb was not pinned.
    assert_eq!(op.intent.fee_rate_sat_per_vb, 2);
    assert_eq!(op.intent.recipients[0].script_hex, "0014deadbeef");

    let swapped = with(serde_json::json!({
        "recipients": [{ "address": ATTACKER, "scriptHex": "0014deadbeef", "amountSat": 40_000 }]
    }));
    assert_intent_mismatch(
        run(swapped, &send_btc_params()),
        &format!("recipient address {ATTACKER} != {ADDRESS}"),
        "swapped recipient address",
    );

    let inflated = with(serde_json::json!({
        "recipients": [{ "address": ADDRESS, "scriptHex": "0014deadbeef", "amountSat": 4_000_000 }]
    }));
    assert_intent_mismatch(
        run(inflated, &send_btc_params()),
        "recipient amountSat 4000000 != 40000",
        "changed amount",
    );

    let extra = with(serde_json::json!({
        "recipients": [
            { "address": ADDRESS, "scriptHex": "0014deadbeef", "amountSat": 40_000 },
            { "address": ATTACKER, "scriptHex": "0014cafe", "amountSat": 100_000 }
        ]
    }));
    assert_intent_mismatch(
        run(extra, &send_btc_params()),
        "expected exactly 1 recipient, got 2",
        "extra recipient",
    );

    // asset.witnessAmountSat is how check 2 accounts for a FOREIGN output;
    // on a plain BTC send there is no such approval to grant.
    let smuggled = with(serde_json::json!({
        "asset": {
            "assetId": "rgb:x", "amount": 1, "recipientId": "wvout:y",
            "witnessAmountSat": 5_000_000, "transportEndpoints": []
        }
    }));
    assert_intent_mismatch(
        run(smuggled, &send_btc_params()),
        "send-btc intent carries an asset",
        "asset smuggled onto a send-btc intent",
    );
    let utxo_shape = with(serde_json::json!({ "utxos": { "upTo": true, "num": 1, "size": 1 } }));
    assert_intent_mismatch(
        run(utxo_shape, &send_btc_params()),
        "send-btc intent carries a utxo shape",
        "utxo shape on a send-btc intent",
    );

    // A pinned fee rate the server did not honour.
    let pinned_fee = PrepareSendBtcParams {
        fee_rate_sat_per_vb: Some(5),
        ..send_btc_params()
    };
    assert_intent_mismatch(
        run(send_btc_intent_json(), &pinned_fee),
        "feeRateSatPerVb 2 != 5",
        "pinned fee rate",
    );
    let honoured = with(serde_json::json!({ "feeRateSatPerVb": 5 }));
    assert_eq!(
        run(honoured, &pinned_fee)
            .unwrap()
            .intent
            .fee_rate_sat_per_vb,
        5
    );

    // No intent at all, an intent that is not an object, a different flow.
    for (body, detail) in [
        (
            serde_json::json!({ "opId": "op-4", "psbt": "cHNidP8=", "expiresAt": 1 }),
            "prepare response carries no intent summary",
        ),
        (
            serde_json::json!({ "opId": "op-4", "psbt": "cHNidP8=", "expiresAt": 1, "intent": null }),
            "prepare response carries no intent summary",
        ),
        (
            serde_json::json!({ "opId": "op-4", "psbt": "cHNidP8=", "expiresAt": 1, "intent": "send_btc" }),
            "prepare response carries no intent summary",
        ),
        (
            prepared(with(serde_json::json!({ "kind": "create_utxos" }))),
            "kind create_utxos != send_btc",
        ),
        (
            prepared(with(serde_json::json!({ "recipients": "none" }))),
            "intent.recipients is not an array",
        ),
    ] {
        let transport = FakeTransport::with(vec![ok(200, body)]);
        assert_intent_mismatch(
            client(&transport, Some("t")).prepare_send_btc(&send_btc_params(), None),
            detail,
            detail,
        );
    }

    // Every mismatch is listed, not just the first.
    let everything = with(serde_json::json!({
        "kind": "send_asset",
        "recipients": [{ "address": ATTACKER, "scriptHex": "0014deadbeef", "amountSat": 1 }],
        "utxos": { "upTo": true, "num": 1, "size": 1 }
    }));
    let reason = match run(everything, &pinned_fee) {
        Err(SdkError::IntentMismatch { reason }) => reason,
        other => panic!("expected IntentMismatch, got {other:?}"),
    };
    for detail in [
        "kind send_asset != send_btc",
        &format!("recipient address {ATTACKER} != {ADDRESS}"),
        "recipient amountSat 1 != 40000",
        "send-btc intent carries a utxo shape",
        "feeRateSatPerVb 2 != 5",
    ] {
        assert!(reason.contains(detail), "{reason:?} lacks {detail:?}");
    }
    assert_eq!(reason.matches("; ").count(), 4, "{reason}");

    // A field verify cannot represent is a mismatch too (fail closed).
    let stringly = with(serde_json::json!({
        "recipients": [{ "address": ADDRESS, "scriptHex": "0014deadbeef", "amountSat": "40000" }]
    }));
    assert_intent_mismatch(
        run(stringly, &send_btc_params()),
        "recipient amountSat 40000 != 40000",
        "string amount is not a number",
    );
    let no_script = with(serde_json::json!({
        "recipients": [{ "address": ADDRESS, "amountSat": 40_000 }]
    }));
    assert_intent_mismatch(
        run(no_script, &send_btc_params()),
        "recipient.scriptHex is not a string",
        "missing scriptHex",
    );
}

#[test]
fn intent_binding_send_asset_rejects_changed_asset_amount_recipient_witness_and_recipients() {
    let run = |intent: serde_json::Value, params: &PrepareSendAssetParams| {
        let transport = FakeTransport::with(vec![ok(200, prepared(intent))]);
        client(&transport, Some("t")).prepare_send_asset(params, None)
    };
    let with_asset = |patch: serde_json::Value| {
        let mut intent = send_asset_intent_json();
        for (k, v) in patch.as_object().unwrap() {
            intent["asset"][k] = v.clone();
        }
        intent
    };

    let op = run(send_asset_intent_json(), &send_asset_params()).unwrap();
    let asset = op.intent.asset.unwrap();
    assert_eq!(asset.witness_amount_sat, None);
    assert_eq!(asset.transport_endpoints, ["http://proxy"]);
    assert_eq!(op.intent.recipients, Vec::<IntentRecipient>::new());

    for (patch, detail) in [
        (
            serde_json::json!({ "assetId": "rgb:evil" }),
            "assetId rgb:evil != rgb:good",
        ),
        (serde_json::json!({ "amount": 1_000 }), "amount 1000 != 10"),
        (
            serde_json::json!({ "recipientId": "utxob:attacker" }),
            "recipientId utxob:attacker != utxob:me",
        ),
        // A foreign witness amount on a blind send: check 2 would account
        // for one foreign output of that size.
        (
            serde_json::json!({ "witnessAmountSat": 5_000_000 }),
            "witnessAmountSat 5000000 != null",
        ),
    ] {
        assert_intent_mismatch(run(with_asset(patch), &send_asset_params()), detail, detail);
    }
    // A missing witnessAmountSat is not "null": `undefined !== null`.
    let mut missing = send_asset_intent_json();
    missing["asset"]
        .as_object_mut()
        .unwrap()
        .remove("witnessAmountSat");
    assert_intent_mismatch(
        run(missing, &send_asset_params()),
        "witnessAmountSat undefined != null",
        "missing witnessAmountSat",
    );
    // The witness case: the caller's amount must come back exactly.
    let witness_params = PrepareSendAssetParams {
        witness_amount_sat: Some(1_000),
        ..send_asset_params()
    };
    assert_intent_mismatch(
        run(send_asset_intent_json(), &witness_params),
        "witnessAmountSat null != 1000",
        "witness amount dropped",
    );
    let witness_ok = run(
        with_asset(serde_json::json!({ "witnessAmountSat": 1_000 })),
        &witness_params,
    )
    .unwrap();
    assert_eq!(
        witness_ok.intent.asset.unwrap().witness_amount_sat,
        Some(1_000)
    );

    // Bitcoin recipients on an asset send, a utxo shape, no asset at all.
    let mut with_recipient = send_asset_intent_json();
    with_recipient["recipients"] =
        serde_json::json!([{ "address": ATTACKER, "scriptHex": "0014cafe", "amountSat": 100_000 }]);
    assert_intent_mismatch(
        run(with_recipient, &send_asset_params()),
        "send-asset intent carries 1 bitcoin recipient(s)",
        "recipient on an asset send",
    );
    let mut with_utxos = send_asset_intent_json();
    with_utxos["utxos"] = serde_json::json!({ "upTo": false, "num": 1, "size": 1 });
    assert_intent_mismatch(
        run(with_utxos, &send_asset_params()),
        "send-asset intent carries a utxo shape",
        "utxo shape on an asset send",
    );
    let mut no_asset = send_asset_intent_json();
    no_asset["asset"] = serde_json::Value::Null;
    assert_intent_mismatch(
        run(no_asset, &send_asset_params()),
        "send-asset intent carries no asset",
        "asset dropped",
    );

    // Transport endpoints are asserted only when pinned.
    let pinned = PrepareSendAssetParams {
        transport_endpoints: Some(vec!["http://mine".into()]),
        ..send_asset_params()
    };
    assert_intent_mismatch(
        run(send_asset_intent_json(), &pinned),
        "transportEndpoints http://proxy != http://mine",
        "pinned endpoints",
    );
    assert!(run(
        with_asset(serde_json::json!({ "transportEndpoints": ["http://mine"] })),
        &pinned
    )
    .is_ok());
    let pinned_fee = PrepareSendAssetParams {
        fee_rate_sat_per_vb: Some(9),
        ..send_asset_params()
    };
    assert_intent_mismatch(
        run(send_asset_intent_json(), &pinned_fee),
        "feeRateSatPerVb 2 != 9",
        "pinned fee",
    );
    // The request body carries every pinned field and omits unset ones.
    let transport = FakeTransport::with(vec![ok(200, prepared(send_asset_intent_json()))]);
    let _ = client(&transport, Some("t")).prepare_send_asset(
        &PrepareSendAssetParams {
            donation: Some(true),
            min_confirmations: Some(3),
            ..send_asset_params()
        },
        None,
    );
    assert_eq!(
        body_json(&transport.seen()[0]),
        serde_json::json!({
            "assetId": "rgb:good", "amount": 10, "recipientId": "utxob:me",
            "donation": true, "minConfirmations": 3
        })
    );
}

#[test]
fn intent_binding_create_utxos_asserts_only_pinned_shape_fields() {
    let run = |intent: serde_json::Value, params: &PrepareCreateUtxosParams| {
        let transport = FakeTransport::with(vec![ok(200, prepared(intent))]);
        client(&transport, Some("t")).prepare_create_utxos(params, None)
    };
    let unpinned = PrepareCreateUtxosParams {
        num: None,
        size: None,
        up_to: None,
        fee_rate_sat_per_vb: None,
    };
    let op = run(create_utxos_intent_json(), &unpinned).unwrap();
    let utxos = op.intent.utxos.unwrap();
    assert_eq!((utxos.up_to, utxos.num, utxos.size), (false, 4, 1_000));
    assert!(run(
        create_utxos_intent_json(),
        &PrepareCreateUtxosParams {
            num: Some(4),
            ..unpinned.clone()
        }
    )
    .is_ok());
    for (params, detail) in [
        (
            PrepareCreateUtxosParams {
                num: Some(8),
                ..unpinned.clone()
            },
            "num 4 != 8",
        ),
        (
            PrepareCreateUtxosParams {
                size: Some(32_000),
                ..unpinned.clone()
            },
            "size 1000 != 32000",
        ),
        (
            PrepareCreateUtxosParams {
                up_to: Some(true),
                ..unpinned.clone()
            },
            "upTo false != true",
        ),
        (
            PrepareCreateUtxosParams {
                fee_rate_sat_per_vb: Some(1),
                ..unpinned.clone()
            },
            "feeRateSatPerVb 2 != 1",
        ),
    ] {
        assert_intent_mismatch(run(create_utxos_intent_json(), &params), detail, detail);
    }
    let mut with_recipient = create_utxos_intent_json();
    with_recipient["recipients"] =
        serde_json::json!([{ "address": ATTACKER, "scriptHex": "0014cafe", "amountSat": 1 }]);
    assert_intent_mismatch(
        run(with_recipient, &unpinned),
        "create-utxos intent carries 1 recipient(s)",
        "recipient on create-utxos",
    );
    let mut with_asset = create_utxos_intent_json();
    with_asset["asset"] = send_asset_intent_json()["asset"].clone();
    assert_intent_mismatch(
        run(with_asset, &unpinned),
        "create-utxos intent carries an asset",
        "asset on create-utxos",
    );
    let mut no_shape = create_utxos_intent_json();
    no_shape["utxos"] = serde_json::Value::Null;
    assert_intent_mismatch(
        run(no_shape, &unpinned),
        "create-utxos intent carries no utxo shape",
        "shape dropped",
    );
}

#[test]
fn gateway_prepared_intent_feeds_verify_and_sign_to_the_rgb_lib_txid() {
    // End to end through the client: the bound intent the fake gateway
    // returned for the fixture PSBT is the very value verify consumes, and
    // signing it reproduces rgb-lib's txid; the signed PSBT then goes back
    // through complete_send_btc.
    let w = wallets();
    let expected_txid = fixture_str(&w.fixture["signing"]["txid"], "signing.txid");
    let transport = FakeTransport::with(vec![
        ok(
            200,
            serde_json::json!({
                "opId": "op-fixture", "psbt": fixture_unsigned(&w), "expiresAt": 1,
                "intent": fixture_send_btc_intent_json(&w)
            }),
        ),
        ok(200, serde_json::json!({ "txid": expected_txid })),
    ]);
    let c = client(&transport, Some("t"));
    let op = c
        .prepare_send_btc(
            &PrepareSendBtcParams {
                address: w.foreign.address_at(false, 0, 0),
                amount_sat: 40_000,
                fee_rate_sat_per_vb: Some(2),
            },
            None,
        )
        .unwrap();
    assert_eq!(op.intent, send_btc_intent(&w));
    let signed = verify_and_sign_psbt(&w.ours.keys, &op.psbt, &params(&w, op.intent, 2_000))
        .expect("bound intent verifies and signs");
    assert_eq!(signed.txid, expected_txid);
    let completed = c
        .complete_send_btc(
            &CompleteParams {
                op_id: op.op_id,
                signed_psbt: signed.signed_psbt.clone(),
            },
            None,
        )
        .unwrap();
    assert_eq!(completed.txid, expected_txid);
    let body = body_json(&transport.seen()[1]);
    assert_eq!(body["opId"], "op-fixture");
    assert_eq!(body["signedPsbt"], signed.signed_psbt);
}

#[test]
fn gateway_requests_never_carry_secrets_and_token_never_renders() {
    let fixture = load_fixture();
    let mnemonic = fixture_mnemonic(&fixture);
    let keys = ClientKeys::from_mnemonic(&mnemonic, BitcoinNetwork::Regtest).unwrap();
    let xpubs = keys.xpubs();
    let token = "tok-SECRET-bearer-8f2a";
    let operator = "op-SECRET-9c1d";

    // One response per call, in the order below.
    let transport = FakeTransport::with(vec![
        ok(
            201,
            serde_json::json!({ "userId": "u", "token": token, "createdAt": 1 }),
        ),
        ok(200, serde_json::json!({ "userId": "u", "createdAt": 1 })),
        ok(
            200,
            serde_json::json!({ "fingerprint": xpubs.fingerprint, "address": "a" }),
        ),
        ok(200, serde_json::json!({ "address": "a" })),
        ok(
            200,
            serde_json::json!({ "btc": { "vanilla": { "settled": 0, "future": 0, "spendable": 0 }, "colored": { "settled": 0, "future": 0, "spendable": 0 } }, "assets": [] }),
        ),
        ok(200, serde_json::json!({ "unspents": [] })),
        ok(200, serde_json::json!({ "transfers": [] })),
        ok(
            200,
            serde_json::json!({ "invoice": "i", "recipientId": "r", "expirationTimestamp": null, "mode": "witness" }),
        ),
        ok(200, serde_json::json!({ "status": "ok" })),
        ok(200, prepared(send_btc_intent_json())),
        ok(200, serde_json::json!({ "txid": "t" })),
        ok(200, prepared(send_asset_intent_json())),
        ok(200, serde_json::json!({ "txid": "t" })),
        ok(200, prepared(create_utxos_intent_json())),
        ok(200, serde_json::json!({ "txid": null, "utxosCreated": 0 })),
        ok(
            200,
            serde_json::json!({ "depositId": "d", "kind": "rgb", "address": null, "invoice": "i", "recipientId": "r" }),
        ),
        ok(
            200,
            serde_json::json!({ "paymentHash": "h", "status": "failed" }),
        ),
        ok(
            200,
            serde_json::json!({ "invoice": "i", "paymentHash": "h" }),
        ),
        ok(
            200,
            serde_json::json!({ "paymentHash": "h", "invoice": "i", "state": "expired", "amtMsat": null, "assetId": null, "assetAmount": null, "createdAt": 1 }),
        ),
        ok(200, serde_json::json!({ "payments": [] })),
        ok(200, serde_json::json!({ "btcMsat": 0, "assets": {} })),
        ok(200, serde_json::json!({ "withdrawalId": "w", "txid": "t" })),
    ]);
    let c = client(&transport, Some(token));
    let created = c.create_user(operator).unwrap();
    assert_eq!(created.token, token);
    // The one record carrying a credential redacts it in Debug.
    let rendered = format!("{created:?}");
    assert!(!rendered.contains(token), "{rendered}");
    assert!(rendered.contains("[redacted]"));
    c.me().unwrap();
    c.register_xpubs(&RegisterXpubsParams {
        vanilla: xpubs.vanilla.clone(),
        colored: xpubs.colored.clone(),
        fingerprint: xpubs.fingerprint.clone(),
    })
    .unwrap();
    c.get_address().unwrap();
    c.get_balances().unwrap();
    c.get_unspents().unwrap();
    c.get_transfers(Some("rgb:x")).unwrap();
    c.receive(&ReceiveParams {
        mode: ReceiveMode::Witness,
        asset_id: None,
        amount: None,
        duration_seconds: Some(60),
        min_confirmations: None,
    })
    .unwrap();
    c.sync().unwrap();
    c.prepare_send_btc(&send_btc_params(), None).unwrap();
    let complete = CompleteParams {
        op_id: "op-1".into(),
        signed_psbt: "cHNidP8=".into(),
    };
    c.complete_send_btc(&complete, None).unwrap();
    c.prepare_send_asset(&send_asset_params(), None).unwrap();
    c.complete_send_asset(&complete, None).unwrap();
    c.prepare_create_utxos(
        &PrepareCreateUtxosParams {
            num: None,
            size: None,
            up_to: None,
            fee_rate_sat_per_vb: None,
        },
        None,
    )
    .unwrap();
    c.complete_create_utxos(&complete, None).unwrap();
    c.prepare_ln_deposit(
        &LnDepositPrepareParams {
            kind: LnAssetKind::Rgb,
            amount_msat: None,
            asset_id: Some("rgb:x".into()),
            amount: Some(1),
        },
        None,
    )
    .unwrap();
    c.pay_ln_invoice(
        &LnPayParams {
            invoice: "lnbcrt1...".into(),
            amt_msat: Some(1),
            asset_amount: None,
        },
        None,
    )
    .unwrap();
    c.create_ln_invoice(&LnInvoiceCreateParams {
        amt_msat: None,
        expiry_sec: Some(60),
        asset_id: Some("rgb:x".into()),
        asset_amount: Some(1),
        description: None,
    })
    .unwrap();
    c.get_ln_invoice("h").unwrap();
    c.list_ln_payments().unwrap();
    c.get_ln_balance().unwrap();
    c.withdraw_ln(
        &LnWithdrawParams {
            kind: LnAssetKind::Rgb,
            address: None,
            amount_sat: None,
            asset_id: Some("rgb:x".into()),
            amount: Some(1),
            recipient_id: Some("bcrt:wvout:x".into()),
            witness_amount_sat: Some(1_000),
            transport_endpoints: Some(vec!["rpc://p".into()]),
            fee_rate_sat_per_vb: Some(2),
        },
        None,
    )
    .unwrap();

    let seen = transport.seen();
    assert_eq!(seen.len(), 22, "all 22 routes exercised");
    let mut registered_xpubs = 0;
    for request in &seen {
        // No body or header carries the mnemonic, a seed or an xprv/tprv.
        let body = request.body.clone().unwrap_or_default();
        assert_no_secret(&body, &mnemonic, &format!("{} body", request.url));
        for (name, value) in &request.headers {
            assert_no_secret(value, &mnemonic, &format!("{} header {name}", request.url));
        }
        assert_no_secret(&request.url, &mnemonic, "url");
        // The bearer token travels in exactly one header of authenticated
        // calls and nowhere else (never in a body, url or other header).
        let bearer = format!("Bearer {token}");
        for (name, value) in &request.headers {
            if name == "authorization" {
                assert_eq!(value, &bearer);
            } else {
                assert!(!value.contains(token), "{name} carries the token");
            }
        }
        assert!(!body.contains(token) && !request.url.contains(token));
        if request.url.ends_with("/v1/wallet/xpubs") {
            registered_xpubs += 1;
            let sent = body_json(request);
            assert_eq!(sent["vanilla"], xpubs.vanilla);
            assert_eq!(sent["colored"], xpubs.colored);
            assert_eq!(sent["fingerprint"], xpubs.fingerprint);
            assert!(xpubs.vanilla.starts_with("tpub") && xpubs.colored.starts_with("tpub"));
        }
        // Debug output of a request redacts credential values.
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(token), "{rendered}");
        assert!(!rendered.contains(operator), "{rendered}");
        assert_no_secret(&rendered, &mnemonic, "request Debug");
    }
    assert_eq!(registered_xpubs, 1);

    // The bearer token never renders in Debug or any error.
    let rendered = format!("{c:?}");
    assert!(!rendered.contains(token), "{rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
    let transport = FakeTransport::with(vec![
        ok(
            401,
            serde_json::json!({ "error": { "code": "UNAUTHORIZED", "message": "bad token" } }),
        ),
        Err(SdkError::Transport {
            reason: "tls handshake failed".into(),
        }),
        ok(200, serde_json::json!({ "opId": 1 })),
        ok(200, prepared(send_btc_intent_json())),
        ok(200, serde_json::json!({})),
    ]);
    let c = client(&transport, Some(token));
    let errors = vec![
        c.me().unwrap_err(),
        c.me().unwrap_err(),
        c.prepare_send_btc(&send_btc_params(), None).unwrap_err(),
        c.prepare_send_btc(
            &PrepareSendBtcParams {
                address: ATTACKER.into(),
                ..send_btc_params()
            },
            None,
        )
        .unwrap_err(),
        c.get_address().unwrap_err(),
        client(&FakeTransport::with(vec![]), None).me().unwrap_err(),
    ];
    assert!(errors
        .iter()
        .any(|e| matches!(e, SdkError::Gateway { status: 401, .. })));
    assert!(errors
        .iter()
        .any(|e| matches!(e, SdkError::Transport { .. })));
    assert!(errors
        .iter()
        .any(|e| matches!(e, SdkError::IntentMismatch { .. })));
    for error in errors {
        for rendered in [format!("{error}"), format!("{error:?}")] {
            assert!(!rendered.contains(token), "{rendered}");
            assert!(!rendered.contains(operator), "{rendered}");
            assert_no_secret(&rendered, &mnemonic, "gateway error");
        }
    }
}

#[test]
fn gateway_source_links_no_network_stack_and_reaches_no_key_material() {
    let src = manifest_dir().join("src");
    let gateway_rs = fs::read_to_string(src.join("gateway.rs")).unwrap();
    // Code only: doc comments legitimately name the invariants they uphold.
    let strip_comments = |text: &str| -> String {
        text.split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let body = strip_comments(&gateway_rs);
    // The transport is a foreign trait: Rust performs no IO.
    assert!(body.contains("#[uniffi::export(with_foreign)]\npub trait HttpTransport: Send + Sync"));
    for forbidden in [
        "std::net",
        "TcpStream",
        "reqwest",
        "ureq",
        "hyper",
        "rustls",
        "openssl",
        "tokio",
        "async fn",
        ".await",
        "unwrap()",
        "expect(",
        "panic!",
        "unreachable!",
        // Key material is unreachable from this module by construction:
        // it never names the mnemonic, seed or private-key types.
        "ClientKeys",
        "Xpriv",
        "SecretKey",
        "Mnemonic",
        "mnemonic",
        "seed",
    ] {
        assert!(
            !body.contains(forbidden),
            "gateway.rs contains {forbidden:?}"
        );
    }
    // json.rs is the only other module the client depends on and is just as
    // strict: no panics on hostile input.
    let json_rs = fs::read_to_string(src.join("json.rs")).unwrap();
    let json_body = strip_comments(&json_rs);
    for forbidden in ["unwrap()", "expect(", "panic!", "unreachable!"] {
        assert!(
            !json_body.contains(forbidden),
            "json.rs contains {forbidden:?}"
        );
    }
    // Idempotency keys come from the OS CSPRNG that bitcoin already links.
    assert!(body.contains("OsRng"));
    let manifest = fs::read_to_string(manifest_dir().join("Cargo.toml")).unwrap();
    for crate_name in ["uuid", "rand =", "serde_json =", "reqwest", "ureq"] {
        let deps = manifest.split("[dev-dependencies]").next().unwrap();
        assert!(
            !deps.contains(crate_name),
            "Cargo.toml gained {crate_name:?}"
        );
    }
    // The uniffi surface exposes the client, the 23 routes and the key generator.
    let route_exports = body.matches("#[uniffi::method(name = \"").count();
    assert_eq!(route_exports, 23, "one uniffi method per route");
    assert!(body.contains("#[uniffi::export(name = \"generate_idempotency_key\")]"));
}

#[test]
fn gateway_hostile_bodies_never_panic() {
    // Every response body here is either accepted or an SdkError, never a
    // panic; the parser also survives deep nesting and junk bytes.
    let bodies = [
        "",
        "null",
        "[]",
        "{",
        "{\"address\":",
        "\u{0}",
        "{\"address\":\"\\ud800\"}",
        "{\"unspents\":[{\"txid\":1}]}",
        "{\"transfers\":[{}]}",
        "{\"btc\":null,\"assets\":[]}",
        "{\"assets\":{\"rgb:x\":-1},\"btcMsat\":0}",
        "{\"assets\":{\"rgb:x\":1.5},\"btcMsat\":0}",
        "{\"intent\":{\"kind\":\"send_btc\",\"recipients\":[null]}}",
        "{\"intent\":{\"kind\":\"send_btc\",\"recipients\":[{}],\"asset\":[],\"utxos\":{}}}",
        "{\"opId\":\"o\",\"psbt\":\"p\",\"expiresAt\":-1,\"intent\":{\"kind\":\"send_btc\",\"feeRateSatPerVb\":2,\"recipients\":[{\"address\":\"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080\",\"scriptHex\":\"00\",\"amountSat\":40000}],\"asset\":null,\"utxos\":null}}",
        &"[".repeat(10_000),
        &format!("{{\"assets\":{}}}", "[".repeat(100)),
    ];
    for body in bodies {
        let responses: Vec<Result<HttpResponse, SdkError>> = (0..7)
            .map(|_| {
                Ok(HttpResponse {
                    status: 200,
                    body: body.to_owned(),
                })
            })
            .collect();
        let transport = FakeTransport::with(responses);
        let c = client(&transport, Some("t"));
        // None of these bodies is a valid response for the route it is fed
        // to, so every call must be an explicit error (a malformed-response
        // `Gateway` or an `IntentMismatch`), never a defaulted value.
        let outcomes: Vec<Result<String, SdkError>> = vec![
            c.get_address().map(|v| format!("{v:?}")),
            c.get_balances().map(|v| format!("{v:?}")),
            c.get_unspents().map(|v| format!("{v:?}")),
            c.get_transfers(None).map(|v| format!("{v:?}")),
            c.get_ln_balance().map(|v| format!("{v:?}")),
            c.prepare_send_btc(&send_btc_params(), None)
                .map(|v| format!("{v:?}")),
            c.list_ln_payments().map(|v| format!("{v:?}")),
        ];
        for outcome in outcomes {
            assert!(
                matches!(
                    &outcome,
                    Err(SdkError::Gateway { code, .. }) if code == "MALFORMED_RESPONSE"
                ) || matches!(&outcome, Err(SdkError::IntentMismatch { .. })),
                "body {body:?}: expected an explicit error, got {outcome:?}"
            );
        }
    }
}
