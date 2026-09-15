# @utexo/minimal-sdk

**Temporary home.** This pnpm workspace implements the first minimum of the Minimal SDK
variant designed in `docs/design/minimal-sdk-and-lightweight-rln.md`: a TypeScript API
gateway (`packages/gateway`) in front of ONE shared RLN instance, a browser/mobile client
SDK (`packages/client-sdk`) that keeps all key material client-side (verify-before-sign),
and an e2e suite (`packages/e2e`) on the repo's regtest infrastructure. It lives inside
the rgb-lightning-node repository only to reuse the regtest stack and stay close to the
design doc; extraction into its own repository (with its own CI) is a later, mechanical
step — no code here depends on the Rust sources.

## Architecture

From the design doc:

```
browser / mobile app
  └─ minimal TS SDK  (keys, PSBT verify + sign, invoice decode)
        │  HTTPS (REST today; GraphQL/gRPC are gateway-layer options)
  API gateway  (per-user auth, per-user scoping + FIFO queue, idempotency keys)
        ├─ per-user watch-only rgb-lib wallets  (PSBT preparation, balances, receives)
        └─ single RLN instance  (admin token; LN channels, swaps, RGB transfers)
              └─ shared esplora + RGB proxy
```

The server prepares transactions on the user's watch-only wallet; the client verifies
against its stated intent and signs; the server broadcasts. Package READMEs:
`packages/gateway/README.md` (config reference, deployment, float caps, the custody
boundary) and `packages/client-sdk/README.md` (quickstart, the verify-before-sign
contract); `packages/e2e/README.md` covers the regtest journey suite.

### Native mobile: one Rust core, two packages

For natively written Android and iOS apps the same client role is filled by **one Rust
crate** exposed to both platforms through uniffi
(`docs/plans/20260915-minimal-mobile-rust-sdk.md`):

```
Android app (Kotlin)                 iOS app (Swift)
  └─ android/  AAR + JNA               └─ apple/  SwiftPM + XCFramework
        └──────────── rust-sdk/  (keys, derive, verify-before-sign, sign, invoice, gateway client)
                          │  HTTP through a host-implemented HttpTransport (OkHttp / URLSession)
                      API gateway  (same REST surface as above)
```

- `rust-sdk/` — the core: `bitcoin` + `bip39` + `thiserror` + `uniffi`, nothing else; no
  rgb-lib, no HTTP or TLS stack. `cargo test` is the gate (99 tests: 68 parity and
  adversarial cases in `tests/parity.rs` plus 31 unit tests, a release size gate, a
  dependency-creep guard). README: `rust-sdk/README.md` (quickstart in Kotlin
  and Swift, the five checks, the `HttpTransport` seam, sizes, mobile runtime constraints).
- `android/` — Gradle library `com.utexo.minimalsdk` (minSdk 24, JNA runtime dependency),
  JNI libs for three ABIs with a 16 KB page-alignment gate and a 3.0 MB arm64 size gate.
- `apple/` — Swift package `MinimalSdk` (iOS 15 / macOS 12), static XCFramework built by
  `scripts/build_apple.sh` on macOS.
- `scripts/` — `generate_bindings.sh` (uniffi library mode, no UDL), `build_android.sh`,
  `build_apple.sh`. CI: `.github/workflows/minimal-sdk-mobile.yaml`.

**The TypeScript SDK stays hand-written and stays shipped.** It is the behavioural
reference the Rust crate was ported from and is the **independent cross-check** on the
Rust implementation, not legacy to be replaced: both read the same rgb-lib-authored
`packages/client-sdk/test/fixtures/rgblib-parity.json` and share no code, so a shared
misreading of BIP-86 or the RGB coin types cannot hide. Web and React Native keep using
it (185.5 KB of pure JS); native Kotlin and Swift apps use the Rust core.

`pnpm-workspace.yaml` is unaffected: it globs `packages/*` only, so the Cargo, Gradle and
SwiftPM directories above are invisible to pnpm and none of the workspace commands below
touch them.

## Deliberately deferred

- **RLN-side Block-3 fixes** (design doc items 4–7) — Rust changes; this workspace
  changes no Rust code, they ship as a separate PR series before scaling user count.
- **Auto-sweep** of the LN float to user keys — the capped float bounds custodial
  exposure first; sweeping adds a client-signing round-trip worth designing properly.
- **Submarine/atomic swaps** for trust-minimized float in/out — weeks of effort on the
  existing swap API; the capped float is the interim control.
- **BOLT12 offers** — stay unexposed to avoid the known double-pay on retry
  (`src/routes.rs:5093-5095`).
- **VSS / encrypted client backup** — the client is stateless between sessions; its only
  durable secret is the mnemonic, backed up as a seed phrase.
- **GraphQL/gRPC front-end** — REST is what RLN speaks today; other transports are a
  gateway-layer swap that changes no SDK surface.
- **Extraction to its own repository** — mechanical; it lives here only to reuse the
  regtest stack during bring-up.

## Workspace commands

```sh
pnpm -C minimal-sdk install
pnpm -C minimal-sdk build   # tsc build of all packages
pnpm -C minimal-sdk test    # unit tests (gateway + client-sdk + the e2e package's
                            # infra-free smoke test; the regtest journey is excluded)
pnpm -C minimal-sdk lint    # eslint + prettier check
pnpm -C minimal-sdk format  # prettier --write
pnpm -C minimal-sdk e2e     # regtest e2e journey (requires local infra, see below)
```

Two gateway suites additionally exercise the **real** rgb-lib backend against regtest and
are skipped unless opted in (`describe.runIf(process.env['WALLET_REGTEST'] === '1')`):

```sh
ESPLORA=1 ./regtest.sh start   # from the repo root, on a fresh chain
WALLET_REGTEST=1 pnpm --filter @utexo/minimal-gateway test wallet-integration
WALLET_REGTEST=1 pnpm --filter @utexo/minimal-gateway test onchain-integration
```

Run `wallet-integration` first: the two share a fixture account, and the on-chain suite
creates colorable UTXOs that would break the other's `INSUFFICIENT_FUNDS` assertion.

### Generated files

- `packages/gateway/src/rln/openapi.ts` — regenerate with
  `pnpm --filter @utexo/minimal-gateway generate:rln-types` whenever the repo-root
  `openapi.yaml` changes an endpoint the gateway calls.
- `packages/client-sdk/test/fixtures/rgblib-parity.json` — regenerate with
  `pnpm --filter @utexo/minimal-client-sdk generate:fixtures` on an `@utexo/rgb-lib` bump.

## Regtest bring-up (verified 2026-09-09, Preflight B)

From the repository root:

```sh
# 1. start bitcoind + electrs (tcp://localhost:50001) + RGB proxy (http://localhost:3000);
#    ESPLORA=1 additionally starts the esplora REST API on http://localhost:3002
ESPLORA=1 ./regtest.sh start

# 2. build (if needed) and start an RLN instance
cargo build
mkdir -p /tmp/rln-data
target/debug/rgb-lightning-node /tmp/rln-data --daemon-listening-port 3101 \
    --ldk-peer-listening-port 9835 --network regtest --disable-authentication

# 3. init + unlock, then verify the node answers
curl -X POST http://localhost:3101/init -H 'Content-Type: application/json' \
    -d '{"password":"nodepassword"}'
curl -X POST http://localhost:3101/unlock -H 'Content-Type: application/json' -d '{
  "password": "nodepassword",
  "ldk_chain_sync": {"mode": "BlockSync", "config": {
    "bitcoind_rpc_username": "user", "bitcoind_rpc_password": "password",
    "bitcoind_rpc_host": "localhost", "bitcoind_rpc_port": 18443}},
  "indexer_url": "127.0.0.1:50001",
  "proxy_endpoint": "rpc://127.0.0.1:3000/json-rpc",
  "announce_addresses": []}'
curl http://localhost:3101/nodeinfo

# teardown (stops containers and deletes data dirs)
./regtest.sh stop
```

`--disable-authentication` is acceptable strictly because RLN listens on localhost and
only the gateway talks to it (design doc invariant I4); never expose RLN publicly.

Fund/mine helpers: `./regtest.sh sendtoaddress <addr> <amount>`, `./regtest.sh mine <blocks>`.

## rgb-lib binding status (verified 2026-09-09, Preflight A)

`@utexo/rgb-lib@0.3.0-beta.18` supports **watch-only** (mnemonic-less) wallets, but its
published JS `wrapper.js` is stale: the compiled native module takes
`rgblib_new_wallet(walletData, keys)` (2 args) while the wrapper passes 1, and several
signatures differ (`send_begin` takes 8 args incl. `expiration_timestamp_opt`,
`blind_receive`/`witness_receive` take an expiration timestamp instead of a duration).
The gateway therefore calls the native module
(`@utexo/rgb-lib-linux-x64/rgblib`) directly through its own thin shim. Verified on
regtest end-to-end with an external signer: watch-only construction
(`keys.mnemonic: null`), `getAddress`, `listUnspents`, `issueAssetNIA`, `blindReceive`,
`witnessReceive`, `createUtxosBegin` → external `signPsbt` → `createUtxosEnd`, and
`sendBegin` → external `signPsbt` → `sendEnd` with the transfer settling on the
recipient. Marshalling rules for the shim:

- all numbers are passed as strings (`feeRate`, `minConfirmations`, `num`, `size`);
- JSON payloads are camelCase (`WalletData`, `SinglesigKeys`, `Recipient`);
- `Assignment` is externally tagged with a JSON number: `{"Fungible": 100}`;
- JS `null` maps to a NULL pointer ONLY for params compiled with the nullable typemap
  (`asset_id_opt`, `num`/`size` opts); `expiration_timestamp_opt` is NOT nullable — always
  pass a concrete unix-timestamp string;
- `send_begin` returns a JSON-serialized object (take `.psbt`), while
  `create_utxos_begin` returns the raw PSBT base64 string.
