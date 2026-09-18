# utexo-minimal-sdk — the Rust core of the minimal mobile SDK

One Rust implementation of everything that guards user funds in the Minimal SDK
variant — key management, taproot derivation, verify-before-sign, signing, invoice
decoding and the gateway client — exposed to **Kotlin** ([`../android`](../android))
and **Swift** ([`../apple`](../apple)) through uniffi. Plan and rationale:
`docs/plans/20260915-minimal-mobile-rust-sdk.md`; architecture and size argument:
`docs/design/mobile-sdk-and-lightweight-uniffi.md`; trust model and invariants I1–I4:
`docs/design/minimal-sdk-and-lightweight-rln.md`.

**This is not the node.** No LDK, no rgb-lib, no axum, no sea-orm, no chain backend,
no HTTP or TLS stack, no async runtime. The library graph is `bitcoin`, `bip39`,
`thiserror` and `uniffi`; `tests/parity.rs` fails the build if anything banned
(`rgb-lib`, `reqwest`, `tokio`, `rustls`, `openssl`) ever resolves.

**The TypeScript client SDK** (`../packages/client-sdk`) is the behavioural reference
this crate was ported from and stays shipped. It is the independent cross-check on this
implementation, not legacy: both read the same rgb-lib-authored parity fixture and share
no code.

**The mnemonic is the user's only backup.** Keys are generated and stay on the device
(invariant I1); the gateway only ever sees the two account xpubs and the master
fingerprint (I2). Nothing in this crate logs, `Debug`-prints or renders a mnemonic,
seed, xprv or private key, including error variants (I3) — the tests assert it.

## Layout

| Module       | What it holds                                                                                                                                                        | TS reference |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| `network.rs` | the four networks, BIP-32 version bytes, rgb-lib coin types, account paths `m/86'/coin'/0'`                                                                          | `network.ts` |
| `keys.rs`    | `ClientKeys`: BIP-39 → BIP-32 vanilla + colored accounts; xpubs and fingerprint are the only public material                                                         | `keys.ts`    |
| `derive.rs`  | taproot `tr(key)` derivation and `match_origin_path`, the single source of truth for path acceptance                                                                 | `derive.ts`  |
| `verify.rs`  | the five checks, `own_derivation` (fingerprint-based key-origin selection)                                                                                           | `verify.ts`  |
| `sign.rs`    | `verify_and_sign_psbt`, the only signing entry point; BIP-341 key-path sign + finalize                                                                               | `sign.ts`    |
| `invoice.rs` | BOLT-11 and RGB invoice decoding                                                                                                                                     | `invoice.ts` |
| `gateway.rs` | `GatewayClient`, the `HttpTransport` foreign trait, intent binding                                                                                                   | `gateway.ts` |
| `ffi.rs`     | the exported free functions (`sdk_version`, `generate_keys`, `derive_taproot_address`, `verify_psbt`, `verify_and_sign_psbt`, `decode_bolt11`, `decode_rgb_invoice`) | —            |

Bindings are generated in uniffi **library mode** from the built library; there is no
UDL file and none may be added (`tests/parity.rs::no_udl_file_exists`).

## Quickstart

The journey is the same on both platforms: generate keys → register xpubs → prepare →
verify → sign → complete. Every call below is **blocking** and must run off the UI
thread (see "Mobile runtime constraints").

### Kotlin

```kotlin
import com.utexo.minimalsdk.*

// 1. Generate keys on the device. Show `mnemonic` once for backup; it never leaves
//    the phone. Restore later with ClientKeys.fromMnemonic(mnemonic, network).
val generated = generateKeys(BitcoinNetwork.MAINNET)
val keys = generated.keys

// 2. Connect. The bearer token comes from the operator-run user bootstrap
//    (POST /v1/users) and is returned exactly once. The transport is yours (below).
val client = GatewayClient("https://gateway.example.com", token, null, OkHttpTransport())

// 3. Register the account xpubs; the gateway builds a per-user watch-only wallet
//    from them and returns the first vault address. Public material only.
val xpubs = keys.xpubs()
val registered = client.registerXpubs(
    RegisterXpubsParams(vanilla = xpubs.vanilla, colored = xpubs.colored, fingerprint = xpubs.fingerprint),
)

// 4. Send BTC: the server prepares, the CLIENT verifies and signs, the server
//    broadcasts. prepareSendBtc binds the returned intent to the request you made
//    (SdkException.IntentMismatch otherwise); verifyAndSignPsbt refuses to sign
//    unless all five checks pass (SdkException.VerificationFailed names the check).
//    Each phase takes its OWN key: the gateway hashes method + path + body, so
//    one key reused across prepare and complete is 409 IDEMPOTENCY_KEY_REUSED.
val prepared = client.prepareSendBtc(
    PrepareSendBtcParams(address = "bc1p…", amountSat = 50_000UL, feeRateSatPerVb = 2UL),
    generateIdempotencyKey(),
)
val signed = verifyAndSignPsbt(
    keys,
    prepared.psbt,
    VerifyParams(intent = prepared.intent, xpubs = xpubs, maxFeeSat = 1_000UL), // user-approved fee budget
)
val txid = client.completeSendBtc(
    CompleteParams(opId = prepared.opId, signedPsbt = signed.signedPsbt),
    generateIdempotencyKey(),
).txid

// 5. If that complete is lost — timeout, crash, or 502 COMPLETE_AMBIGUOUS — do
//    NOT prepare a replacement. Read the operation back; mayHaveBroadcast true
//    means the transaction may already be on the network, so retry complete.
val status = client.getOnchainOperation(prepared.opId)
if (status.mayHaveBroadcast) { /* retry completeSendBtc with a fresh key */ }
```

A transport over `HttpURLConnection` (OkHttp works the same way; only `send` exists):

```kotlin
class OkHttpTransport : HttpTransport {
    override fun send(request: HttpRequest): HttpResponse {
        val conn = (java.net.URL(request.url).openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = if (request.method == HttpMethod.GET) "GET" else "POST"
            connectTimeout = request.timeoutMs.toInt()
            readTimeout = request.timeoutMs.toInt()
            request.headers.forEach { (name, value) -> setRequestProperty(name, value) }
        }
        try {
            request.body?.let { body -> conn.doOutput = true; conn.outputStream.use { it.write(body.toByteArray()) } }
            val status = conn.responseCode
            val stream = if (status < 400) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() } ?: ""
            return HttpResponse(status.toUShort(), body)
        } catch (e: java.io.IOException) {
            throw SdkException.Transport(e.message ?: "io error") // never include headers: they carry the token
        } finally {
            conn.disconnect()
        }
    }
}
```

### Swift

```swift
import MinimalSdk

// 1. Generate keys on the device. Show `mnemonic` once for backup; it never leaves
//    the phone. Restore later with ClientKeys.fromMnemonic(mnemonic:network:).
let generated = try generateKeys(network: .mainnet)
let keys = generated.keys

// 2. Connect. URLSessionHttpTransport ships with the package; any HttpTransport
//    conformance can replace it.
let client = GatewayClient(baseUrl: "https://gateway.example.com", token: token,
                           timeoutMs: nil, transport: URLSessionHttpTransport())

// 3. Register the account xpubs (public material only).
let xpubs = keys.xpubs()
let registered = try client.registerXpubs(
    params: RegisterXpubsParams(vanilla: xpubs.vanilla, colored: xpubs.colored, fingerprint: xpubs.fingerprint))

// 4. Send BTC: prepare (intent bound to the request, SdkError.IntentMismatch
//    otherwise) → verify and sign (SdkError.VerificationFailed names the failed
//    check; nothing is signed) → complete.
//    Each phase takes its OWN key: the gateway hashes method + path + body, so
//    one key reused across prepare and complete is 409 IDEMPOTENCY_KEY_REUSED.
let prepared = try client.prepareSendBtc(
    params: PrepareSendBtcParams(address: "bc1p…", amountSat: 50_000, feeRateSatPerVb: 2),
    idempotencyKey: try generateIdempotencyKey())
let signed = try verifyAndSignPsbt(
    keys: keys, psbt: prepared.psbt,
    params: VerifyParams(intent: prepared.intent, xpubs: xpubs, maxFeeSat: 1_000, // user-approved fee budget
                         changeScanWindow: nil, maxOwnOutputIndex: nil))
let txid = try client.completeSendBtc(
    params: CompleteParams(opId: prepared.opId, signedPsbt: signed.signedPsbt),
    idempotencyKey: try generateIdempotencyKey()).txid

// 5. If that complete is lost — timeout, crash, or 502 COMPLETE_AMBIGUOUS — do
//    NOT prepare a replacement. Read the operation back; mayHaveBroadcast true
//    means the transaction may already be on the network, so retry complete.
let status = try client.getOnchainOperation(opId: prepared.opId)
if status.mayHaveBroadcast { /* retry completeSendBtc with a fresh key */ }
```

Asset sends (`prepareSendAsset` / `completeSendAsset`) and colorable-UTXO creation
(`prepareCreateUtxos` / `completeCreateUtxos`) follow the same prepare → verify-and-sign
→ complete shape. Receiving (`receive`), balances, unspents, transfers, LN float
deposits, invoices, payments and withdrawals round out `GatewayClient`;
`decodeBolt11` / `decodeRgbInvoice` decode invoices locally for display before paying.
Money-moving calls take an idempotency key: retry the **same** call with the **same**
key to get the cached response instead of a duplicate spend. The key is scoped to one
request — the gateway hashes method, path and body — so `prepare` and `complete` each
need their own; reusing one across both is `409 IDEMPOTENCY_KEY_REUSED`.

`getOnchainOperation(opId)` reads a prepared operation's durable state and is the
recovery path when a `complete` result is lost. It is a read: no idempotency key, and the
gateway does not queue it behind that user's wallet work, so it answers even while the
completion it asks about is still running. `mayHaveBroadcast == true` means the wallet
failed _after_ rgb-lib may already have broadcast — retry `complete` to finish the
bookkeeping rather than sending again. It stays true on an expired operation, because
expiry does not un-broadcast a transaction.

## The verify-before-sign contract

Signing is never blind. `verify_and_sign_psbt` is the only signing entry point; it runs
`verify_psbt` internally and refuses on any failure, before a single input is signed.
`verify_psbt` can also be called on its own to show the user what they are about to
approve. It never errors and never panics on hostile input: a malformed PSBT is a
verdict with all five checks failed, not a crash. The five checks, in evaluation order
and with the same wire names as the TypeScript SDK:

1. **`inputs-own` — every input is ours.** The input's key-origin entry is selected **by
   our master fingerprint, never by path shape**, and its path must re-derive from _our_
   xpubs to the exact script being spent. Inputs are accepted on either account and at
   any index: this is what a hostile PSBT can least fake.
2. **`recipients-match` — recipient outputs match the user-stated intent.** Script and
   amount, matched as a multiset. The expected script is **re-derived from the
   human-readable address** the user reviews; the server's `script_hex` is only
   cross-checked against it, otherwise a hostile gateway could pair the intended address
   with an attacker script and both would "match". Witness asset sends additionally
   require exactly one foreign output carrying exactly the approved witness amount.
3. **`change-own` — change pays only us, at a recoverable path.** Every output that is
   not an intended recipient, the approved witness output or an OP_RETURN must re-derive
   from our vanilla or colored account at **keychain 0 and index ≤ `max_own_output_index`**
   (default 10 000). Any index under the account xpub is technically the user's, but only
   indexes a descriptor wallet scans are recoverable, so a hostile gateway must not be
   able to park "change" at index 10⁸. Outputs with no key-origin metadata are accepted
   only if they match a script within the first `change_scan_window` indexes (default 30;
   0 requires metadata on every output). The input/output asymmetry (inputs: any path;
   outputs: keychain 0, bounded) is deliberate.
4. **`fee-budget` — inputs − outputs is positive and at most `max_fee_sat`**, the fee
   budget the user approved.
5. **`opret-zero` — OP_RETURN outputs carry 0 sats.** The RGB opret commitment may exist
   but may not carry value.

**Intent binding is what makes check 2 non-vacuous.** The intent is server-produced; on
its own it proves nothing against a hostile gateway, which can put an attacker output in
the PSBT and the same attacker output in the intent. `prepare_send_btc`,
`prepare_send_asset` and `prepare_create_utxos` therefore compare the returned intent
field by field against the request you made (kind, recipient address and amount, asset
id, amount and recipient id, witness amount, recipient count, no smuggled asset or UTXO
shape, and any optional you pinned such as the fee rate) and return `IntentMismatch`
listing every divergence before the intent can reach `verify_psbt`. Build an intent some
other way and that binding is yours to make.

**Decoys.** A PSBT may carry several key-origin entries per input. Verify selects the
entry by our fingerprint, and sign signs with the very entry verify proved, so a decoy
entry with a foreign fingerprint ordered first cannot divert signing to a key no check
covered. `match_origin_path` is the single path-acceptance rule shared by verify and by
`private_key_for_path`, so the two cannot drift apart.

**Stated limitation.** The checks verify all _bitcoin-value_ movement. RGB allocations
on the spent inputs are **not verifiable client-side**: the opret commitment is opaque
here, so every server-prepared **colored** spend trusts the gateway for the RGB state
transition at send time (design doc, "send-time trust"; `verify.ts:11-13`). The
mitigations are the gateway's, not this crate's.

## The `HttpTransport` extension point

Rust performs no network IO. `GatewayClient` builds every request (method, absolute
percent-encoded URL, lowercase headers including `authorization`, `idempotency-key` and
`content-type`, optional UTF-8 JSON body, timeout) and parses every response; the host
app moves the bytes through one foreign-implemented method:

```rust
#[uniffi::export(with_foreign)]
pub trait HttpTransport: Send + Sync {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, SdkError>;
}
```

- Return `HttpResponse { status, body }` for **any** HTTP status, 4xx and 5xx included;
  Rust turns those into `SdkError::Gateway { status, code, detail }`.
- Return `SdkError::Transport { reason }` only when no HTTP status exists (DNS, TLS,
  timeout). Never put request headers in the reason: they carry the bearer token.
- Anything else the transport throws (a Kotlin `RuntimeException`, a Swift `Error` that is
  not `SdkError`) is mapped by Rust to `SdkError::Transport` with uniffi's diagnostic as
  the reason. It never surfaces as an internal error or a crash; the smoke tests on both
  bindings throw a foreign exception through Rust to prove it.
- The call is synchronous from Rust's side, so there is no async-over-FFI; the transport
  may block. Kotlin: OkHttp or `HttpURLConnection`. Swift: the shipped
  `URLSessionHttpTransport` (ephemeral session, blocks on a semaphore bounded by
  `timeout_ms`).
- Rust never renders the bearer token into an error, and its `Debug` for `HttpRequest`
  and `CreatedUser` redacts it (asserted in `tests/parity.rs`; the binding smoke tests
  assert every error is token-free). That redaction stops at the FFI: over uniffi
  `HttpRequest` is a plain Kotlin `data class` / Swift `struct` whose default `toString()`
  prints the headers verbatim, so a transport must never log the request it receives.

## Mobile runtime constraints (design doc Block 3) and this SDK's answer

The design doc lists four constraints for a node on the phone. Being explicit about
which apply here is what makes the minimal variant's case.

- **Process death is normal.** _Applies, cheaply._ This is a **stateless** client: it
  holds no channel state, no database, no background task. Process death costs nothing
  beyond an in-flight request. Hold the mnemonic in the platform keystore and re-create
  `ClientKeys` with `fromMnemonic` on restore; `GatewayClient` is re-created for free.
  A prepared-but-unsigned operation simply expires on the gateway (`PreparedOp.expires_at`).
- **Every binding call is blocking.** _Applies, and is stated plainly:_ every uniffi call
  runs on the calling thread. `verify_and_sign_psbt` is milliseconds of secp256k1 work;
  every `GatewayClient` call blocks for the whole HTTP round trip inside your transport.
  **Never call the SDK on the Android main thread** (an ANR, exactly as the design doc
  flags for the node SDK — it applies to any uniffi surface) **or on the iOS main queue.**
  Use a coroutine on `Dispatchers.IO`, a `Task.detached`, or a background queue.
- **The fail-fast watchdog.** _Does not apply._ There is no node, no event loop and no
  `process::exit`. The release profile keeps `panic = "unwind"` so uniffi converts any
  Rust panic into a foreign exception; every exported function returns a typed error and
  `verify_psbt` returns a failed verdict on hostile input.
- **Battery, data and chain backends.** _Does not apply._ No chain sync, no indexer
  polling, no peer connections. The only network traffic is the HTTPS calls the app makes
  through its own transport, when the user acts.

## Measured sizes

Release profile `opt-level = "z"`, thin LTO, `codegen-units = 1`, `strip = "symbols"`,
measured 2026-09-15; host cdylib re-measured 2026-09-18.

| Artifact                                    |                       Raw |     gzip -9 | Note                                                                                    |
| ------------------------------------------- | ------------------------: | ----------: | --------------------------------------------------------------------------------------- |
| Host `x86_64-unknown-linux-gnu` cdylib      |               2 502 000 B | 1 685 630 B | size gate in `tests/parity.rs`: < 2 600 000 B                                           |
| Android `arm64-v8a` `.so` (NDK r29)         |               2 366 720 B | 1 689 588 B | gate in `../scripts/build_android.sh`: < 3 000 000 B; `.text` 640 KB, `.rodata` 1.30 MB |
| Android `armeabi-v7a` / `x86_64` `.so`      | 1 992 820 B / 2 508 984 B |           — |                                                                                         |
| Android AAR (3 ABIs + 514 KB `classes.jar`) |               5 449 477 B |           — | a device installs one slice                                                             |
| JNA 5.14.0 AAR (consumer-side dependency)   |                 517 894 B |           — | uniffi's Kotlin bindings need it                                                        |
| iOS                                         |    not an artifact number |             | see below                                                                               |

About 1.06 MB of every slice is libsecp256k1's precomputed tables, which every secp256k1
binding (Rust or Kotlin) carries. The plan's scratch measurement (derive/PSBT/sign only)
was 1.94 MB; the finished crate adds the gateway client, the JSON codec and both invoice
decoders for the difference.

- **Raw vs compressed.** Android install size tracks the **raw** number: APKs and App
  Bundles store native libraries uncompressed (`extractNativeLibs=false`, default since
  API 23) so they can be page-mapped. The gzip column is what a download costs, not
  what the device keeps. What an arm64 device installs is one slice plus JNA,
  **≈ 2.88 MB**, against ≈ 1.9 MB for a pure-Kotlin SDK that avoids JNA.
- **iOS: measure the app-size delta, not the archive.** iOS links statically and the app
  linker dead-strips the archive, so the `.a` size is not what the user downloads. The
  number that matters is the delta in the app's installed size with and without the SDK
  linked, on a device build with App Thinning; expect the Android arm64 slice as an
  upper bound, less after dead-stripping. `build_apple.sh` prints archive sizes and has
  no gate by design.
- **16 KB page alignment.** Every `PT_LOAD` segment of every Android `.so` is aligned to
  16 384 bytes (measured `0x4000` on all three ABIs). NDK r28+ aligns the 64-bit ABIs by
  default but leaves `armeabi-v7a` at 4 096, so `build_android.sh` passes
  `-Wl,-z,max-page-size=16384` to every target and fails the build on any misaligned
  segment. Required for native code targeting Android 15+.

## Building and testing

```sh
# Rust: the real gate — 99 tests (31 unit + 68 in tests/parity.rs), the size gate and
# the dependency-creep guard.
cargo test --manifest-path minimal-sdk/rust-sdk/Cargo.toml

# Android: bindings, host cdylib, Kotlin smoke, cargo ndk for 3 ABIs, gates, AAR.
# The Gradle wrapper lives in minimal-sdk/android; there is none at the repo root.
JAVA_HOME=~/.jdks/temurin-17 ./minimal-sdk/android/gradlew -p minimal-sdk/android test assembleRelease

# Apple (macOS + Xcode): 5 targets → XCFramework → Swift smoke on the macOS slice.
minimal-sdk/scripts/build_apple.sh && swift test --package-path minimal-sdk/apple
```

`minimal-sdk/scripts/generate_bindings.sh <kotlin|swift> [output_dir] [library_path]`
regenerates bindings from an unstripped host debug build (library mode reads the
`UNIFFI_META_*` symbols, which the release profile strips; the metadata is
target-independent); pass `library_path` to reuse an existing build. The other two
scripts' options are listed in `../android/README.md` (`build_android.sh`) and
`../apple/README.md` (`build_apple.sh`). CI is
`.github/workflows/minimal-sdk-mobile.yaml`: the Rust job is the gate, the Android job
runs the Gradle command above plus the alignment and size checks, the macOS job is the
only place the XCFramework is assembled.

### Parity: what is verified, and where

The tests read `../packages/client-sdk/test/fixtures/rgblib-parity.json` by relative
path. It was generated from the real `@utexo/rgb-lib` binding and is never copied or
regenerated here: one rgb-lib-authored ground truth, checked by an implementation that
shares no code with it. Regenerating the fixture re-runs the whole suite in CI.

| Acceptance item                                                            | Test (`tests/parity.rs` unless noted)                                                                                                                            | Result 2026-09-15                                                                                                                                 |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Account xpubs + master fingerprint `73c5da0a` for all four networks        | `keys_all_four_networks_match_rgb_lib_fixture_exactly`                                                                                                           | pass                                                                                                                                              |
| All ten regtest addresses (5 vanilla + 5 colored, indexes 0..4)            | `derive_reproduces_rgb_lib_regtest_addresses_at_keychain_0_indexes_0_to_4`                                                                                       | pass                                                                                                                                              |
| Fixture PSBT signs to `signing.txid` with a verifying BIP-340 signature    | `sign_fixture_psbt_matches_rgb_lib_txid_with_a_valid_key_path_signature`                                                                                         | pass; txid parity + signature validity, never witness bytes (BIP-340 is randomized)                                                               |
| Each of the five checks fails alone on its own tampering                   | `check1_…inputs_own`, `check2_…recipients_match` (×3), `check3_…change_own` (×2), `check4_…fee_budget`, `check5_…opret_zero`                                     | pass                                                                                                                                              |
| Decoy key-origin entry cannot divert selection or signing                  | `decoy_key_origin_entry_does_not_divert_selection`, `sign_through_a_decoy_key_origin_entry_ordered_before_ours`                                                  | pass                                                                                                                                              |
| Intent binding fires on every tamper shape                                 | `intent_binding_send_btc_…`, `intent_binding_send_asset_…`, `intent_binding_create_utxos_…`                                                                      | pass                                                                                                                                              |
| Hostile or truncated PSBTs never panic                                     | `garbage_and_truncated_psbts_fail_all_five_without_panicking`, `gateway_hostile_bodies_never_panic`                                                              | pass                                                                                                                                              |
| No secret ever renders                                                     | `keys_debug_and_xpubs_render_no_secret`, `sign_errors_never_render_key_material_and_never_panic`, `gateway_requests_never_carry_secrets_and_token_never_renders` | pass                                                                                                                                              |
| No `rgb-lib` / `reqwest` / `tokio` / TLS crate in the graph                | `dependency_creep_guard` (+ `cargo tree -i` for each: no match)                                                                                                  | pass; 59 graph entries                                                                                                                            |
| Size gate                                                                  | `size_gate_release_cdylib_under_budget`                                                                                                                          | pass, 2 491 688 B                                                                                                                                 |
| Kotlin smoke (15 cases) through JNA, both variants                         | `../android/src/test/kotlin/…/SmokeTest.kt`                                                                                                                      | pass                                                                                                                                              |
| Swift smoke (17 cases, 3 of them on the shipped `URLSessionHttpTransport`) | `../apple/Tests/MinimalSdkTests/SmokeTests.swift`                                                                                                                | pass on Linux (Swift 6.0.3, host cdylib); on macOS the `apple` job of `minimal-sdk-mobile.yaml` runs the same suite against the XCFramework slice |

The Kotlin and Swift suites are deliberately smoke-only: they prove the binding surface
(every lowering shape the API uses: objects, records with optionals, lists, maps and
enums, the typed errors), the native load and the foreign transport end to end, in both
directions (a transport that throws the declared error and one that throws a foreign
exception). Every deep assertion lives once, in Rust.
