//! Thin typed client for the minimal gateway API, and the intent binding
//! that makes verify-before-sign's check 2 non-vacuous.
//!
//! **Rust performs no network IO.** The host app supplies an
//! [`HttpTransport`] (OkHttp/`HttpURLConnection` on Android, `URLSession`
//! on iOS) through uniffi's foreign-trait mechanism; this crate links no HTTP
//! or TLS stack. The call is synchronous from Rust's side, so there is no
//! async-over-FFI: the host is expected to call the client off its UI thread.
//!
//! Money-moving calls carry an `Idempotency-Key`; one is generated per
//! logical operation unless the caller pins its own (retry the SAME operation
//! with the SAME key to get the cached response instead of a duplicate spend).
//!
//! Invariants (design doc I1–I4): only account xpubs and the master
//! fingerprint ever appear in a request; no mnemonic, seed or xprv is a
//! request field or reachable from this module; the bearer token is never
//! rendered into an error or `Debug` output.
//!
//! Behavioural reference: `minimal-sdk/packages/client-sdk/src/gateway.ts`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::rand::{rngs::OsRng, RngCore};

use crate::json::{self, Json, ObjectBuilder};
use crate::verify::{IntentAsset, IntentKind, IntentRecipient, IntentUtxos, OnchainIntent};
use crate::{SdkError, SdkResult};

/// Default request timeout handed to the transport, as in the TS client.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// Transport seam
// ---------------------------------------------------------------------------

/// HTTP method. The gateway API uses only these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HttpMethod {
    Get,
    Post,
}

impl HttpMethod {
    pub fn name(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        }
    }
}

/// One request for the host transport to perform, exactly as built: the
/// transport must send it verbatim (method, absolute URL, every header, the
/// body if any) and must not add, drop or rewrite headers.
///
/// The redacting `Debug` below exists only on the Rust side. Over uniffi this
/// is a Kotlin `data class` / Swift `struct` whose default `toString()` /
/// `String(describing:)` prints `headers` verbatim, bearer token included:
/// a host transport must never log the request it receives.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpRequest {
    pub method: HttpMethod,
    /// Absolute URL, already percent-encoded.
    pub url: String,
    /// Lowercase header names. Includes `authorization` on authenticated
    /// calls, `idempotency-key` on money-moving calls and `content-type`
    /// when a body is present.
    pub headers: HashMap<String, String>,
    /// UTF-8 JSON body, `None` for GET and body-less POSTs.
    pub body: Option<String>,
    /// Total time the transport may spend before giving up with
    /// `SdkError::Transport`.
    pub timeout_ms: u64,
}

/// Header names whose values are credentials: redacted in `Debug`.
const SECRET_HEADERS: &[&str] = &["authorization", "x-operator-token"];

/// Renders every header **name** but redacts credential values, so a host
/// app that logs requests never logs the bearer or operator token.
impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| {
                if SECRET_HEADERS.contains(&k.as_str()) {
                    (k.as_str(), "[redacted]")
                } else {
                    (k.as_str(), v.as_str())
                }
            })
            .collect();
        names.sort_unstable();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &names)
            .field("body", &self.body)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

/// What the transport got back. Any status is acceptable here: status
/// mapping (2xx vs error body) is done in Rust.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpResponse {
    pub status: u16,
    /// Response body as text (may be empty or non-JSON; Rust copes).
    pub body: String,
}

/// The network seam, implemented by the host app (modelled on the node's
/// `ExternalSignerHost`). Return `Ok` for **any** HTTP status the server
/// answered with; return `Err(SdkError::Transport { .. })` only when no
/// response was obtained (DNS, connect, TLS, timeout). Never include
/// request headers in the error reason.
#[uniffi::export(with_foreign)]
pub trait HttpTransport: Send + Sync {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, SdkError>;
}

// ---------------------------------------------------------------------------
// Wire types (kept in sync with the gateway's OpenAPI schema)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct CreatedUser {
    pub user_id: String,
    /// The per-user bearer token. Store it in the platform keystore.
    pub token: String,
    pub created_at: u64,
}

/// Renders the token as `[redacted]`: this is the one record that carries a
/// credential, and a host app may log the value it just received.
impl fmt::Debug for CreatedUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreatedUser")
            .field("user_id", &self.user_id)
            .field("token", &"[redacted]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MeInfo {
    pub user_id: String,
    pub created_at: u64,
}

/// Public registration material: account xpubs and the master fingerprint
/// (`ClientKeys::xpubs()`). The only key material that ever leaves the device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RegisterXpubsParams {
    pub vanilla: String,
    pub colored: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RegisteredXpubs {
    pub fingerprint: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WalletAddress {
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Balance {
    pub settled: u64,
    pub future: u64,
    pub spendable: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BtcBalances {
    pub vanilla: Balance,
    pub colored: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AssetBalance {
    pub asset_id: String,
    pub schema: String,
    pub ticker: Option<String>,
    pub name: String,
    pub precision: u8,
    pub balance: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WalletBalances {
    pub btc: BtcBalances,
    pub assets: Vec<AssetBalance>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnspentAllocation {
    pub asset_id: Option<String>,
    pub amount: Option<u64>,
    pub settled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WalletUnspent {
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub colorable: bool,
    pub allocations: Vec<UnspentAllocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WalletUnspents {
    pub unspents: Vec<WalletUnspent>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WalletTransfer {
    pub idx: u64,
    pub asset_id: Option<String>,
    pub amount: Option<u64>,
    pub kind: String,
    pub status: String,
    pub txid: Option<String>,
    pub recipient_id: Option<String>,
    pub expiration: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WalletTransfers {
    pub transfers: Vec<WalletTransfer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ReceiveMode {
    Blind,
    Witness,
}

impl ReceiveMode {
    fn wire(self) -> &'static str {
        match self {
            ReceiveMode::Blind => "blind",
            ReceiveMode::Witness => "witness",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "blind" => Some(ReceiveMode::Blind),
            "witness" => Some(ReceiveMode::Witness),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReceiveParams {
    pub mode: ReceiveMode,
    pub asset_id: Option<String>,
    pub amount: Option<u64>,
    pub duration_seconds: Option<u64>,
    pub min_confirmations: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReceiveResult {
    pub invoice: String,
    pub recipient_id: String,
    pub expiration_timestamp: Option<u64>,
    pub mode: ReceiveMode,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncResult {
    pub status: String,
}

/// A prepared on-chain operation whose `intent` has already been bound to
/// the caller's request (see [`GatewayClient::prepare_send_btc`]). Hand
/// `intent` to `verify_and_sign_psbt` as-is.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PreparedOp {
    pub op_id: String,
    pub psbt: String,
    pub intent: OnchainIntent,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PrepareSendBtcParams {
    pub address: String,
    pub amount_sat: u64,
    pub fee_rate_sat_per_vb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PrepareSendAssetParams {
    pub asset_id: String,
    pub amount: u64,
    pub recipient_id: String,
    /// Required for witness (`wvout`) recipients; must be unset for blind.
    pub witness_amount_sat: Option<u64>,
    pub transport_endpoints: Option<Vec<String>>,
    pub donation: Option<bool>,
    pub min_confirmations: Option<u32>,
    pub fee_rate_sat_per_vb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PrepareCreateUtxosParams {
    pub num: Option<u32>,
    pub size: Option<u64>,
    pub up_to: Option<bool>,
    pub fee_rate_sat_per_vb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CompleteParams {
    pub op_id: String,
    /// The signed+finalized PSBT from `verify_and_sign_psbt`.
    pub signed_psbt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CompleteResult {
    pub txid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CreateUtxosCompleteResult {
    pub txid: Option<String>,
    pub utxos_created: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OperationState {
    Pending,
    Completed,
    Expired,
}

impl OperationState {
    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(OperationState::Pending),
            "completed" => Some(OperationState::Completed),
            "expired" => Some(OperationState::Expired),
            _ => None,
        }
    }
}

/// Durable state of a prepared on-chain operation, for recovery after the
/// outcome of a `complete` call was lost — a timeout, a crash, or the 502
/// `COMPLETE_AMBIGUOUS` the gateway returns when its wallet failed *after*
/// rgb-lib may already have broadcast.
///
/// `may_have_broadcast` is the field that matters in that case: rgb-lib
/// broadcasts before it writes its bookkeeping, so a txid can be recorded on an
/// operation that never completed. When it is true the transaction may already
/// be on the network — retry `complete` (safe, and it finishes the bookkeeping)
/// rather than preparing a second operation. It stays true on an `Expired`
/// operation, because expiry does not un-broadcast a transaction.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OperationStatus {
    pub op_id: String,
    pub kind: IntentKind,
    pub state: OperationState,
    /// Final txid once completed; the possibly-broadcast txid while ambiguous.
    pub txid: Option<String>,
    pub may_have_broadcast: bool,
    /// The same intent summary `prepare` returned.
    pub intent: OnchainIntent,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LnAssetKind {
    Btc,
    Rgb,
}

impl LnAssetKind {
    fn wire(self) -> &'static str {
        match self {
            LnAssetKind::Btc => "btc",
            LnAssetKind::Rgb => "rgb",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "btc" => Some(LnAssetKind::Btc),
            "rgb" => Some(LnAssetKind::Rgb),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnDepositPrepareParams {
    pub kind: LnAssetKind,
    /// Declared BTC deposit amount (cap check), required for kind `Btc`.
    pub amount_msat: Option<u64>,
    pub asset_id: Option<String>,
    pub amount: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnDepositPrepareResult {
    pub deposit_id: String,
    pub kind: LnAssetKind,
    /// Node-owned BTC target address (kind `Btc`).
    pub address: Option<String>,
    /// RGB invoice to pay into the node (kind `Rgb`).
    pub invoice: Option<String>,
    pub recipient_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnPayParams {
    pub invoice: String,
    /// Required when the invoice carries no amount.
    pub amt_msat: Option<u64>,
    pub asset_amount: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LnPaymentStatus {
    Pending,
    Succeeded,
    Failed,
}

impl LnPaymentStatus {
    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(LnPaymentStatus::Pending),
            "succeeded" => Some(LnPaymentStatus::Succeeded),
            "failed" => Some(LnPaymentStatus::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnPayResult {
    pub payment_hash: String,
    pub status: LnPaymentStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnInvoiceCreateParams {
    pub amt_msat: Option<u64>,
    pub expiry_sec: Option<u32>,
    pub asset_id: Option<String>,
    pub asset_amount: Option<u64>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnInvoiceCreated {
    pub invoice: String,
    pub payment_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LnInvoiceState {
    Pending,
    Settled,
    Expired,
}

impl LnInvoiceState {
    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(LnInvoiceState::Pending),
            "settled" => Some(LnInvoiceState::Settled),
            "expired" => Some(LnInvoiceState::Expired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnInvoiceInfo {
    pub payment_hash: String,
    pub invoice: String,
    pub state: LnInvoiceState,
    pub amt_msat: Option<u64>,
    pub asset_id: Option<String>,
    pub asset_amount: Option<u64>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LnPaymentDirection {
    Inbound,
    Outbound,
}

impl LnPaymentDirection {
    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "inbound" => Some(LnPaymentDirection::Inbound),
            "outbound" => Some(LnPaymentDirection::Outbound),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnPaymentEntry {
    pub payment_hash: String,
    pub direction: LnPaymentDirection,
    pub status: LnPaymentStatus,
    pub amt_msat: Option<u64>,
    pub asset_id: Option<String>,
    pub asset_amount: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnPayments {
    pub payments: Vec<LnPaymentEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnBalance {
    pub btc_msat: u64,
    /// Asset id → amount.
    pub assets: HashMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnWithdrawParams {
    pub kind: LnAssetKind,
    pub address: Option<String>,
    pub amount_sat: Option<u64>,
    pub asset_id: Option<String>,
    pub amount: Option<u64>,
    pub recipient_id: Option<String>,
    /// Required when `recipient_id` is a witness (`<chain>:wvout:…`) beneficiary.
    pub witness_amount_sat: Option<u64>,
    pub transport_endpoints: Option<Vec<String>>,
    pub fee_rate_sat_per_vb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LnWithdrawResult {
    pub withdrawal_id: String,
    pub txid: String,
}

// ---------------------------------------------------------------------------
// Idempotency keys and URL encoding
// ---------------------------------------------------------------------------

/// RFC-4122 version-4 id from the OS cryptographic RNG (the `rand` that
/// `bitcoin`'s `rand-std` feature already links; no new dependency). Used
/// for idempotency keys: unguessable, so a third party cannot collide a
/// retry and read back another user's cached response.
pub fn generate_idempotency_key() -> SdkResult<String> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| SdkError::Internal {
            reason: "operating system RNG unavailable".into(),
        })?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes.to_lower_hex_string();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// `encodeURIComponent`: everything but `A-Z a-z 0-9 - _ . ! ~ * ' ( )` is
/// percent-encoded as UTF-8 bytes. RGB asset ids carry `:` and payment
/// hashes come straight from callers: an unencoded value could retarget the
/// request to a different route.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(byte as char),
            _ => {
                // `write!` into a String cannot fail.
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Typed gateway client. Construct once per user session with the bearer
/// token; `create_user` is the only call that works without one.
#[derive(uniffi::Object)]
pub struct GatewayClient {
    base_url: String,
    token: Option<String>,
    timeout_ms: u64,
    transport: Arc<dyn HttpTransport>,
}

/// Renders the base URL and whether a token is configured — never the token.
impl fmt::Debug for GatewayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayClient")
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

struct RequestSpec<'a> {
    method: HttpMethod,
    path: String,
    body: Option<Json>,
    extra_headers: Vec<(&'static str, &'a str)>,
    auth: bool,
}

impl<'a> RequestSpec<'a> {
    fn get(path: impl Into<String>) -> Self {
        RequestSpec {
            method: HttpMethod::Get,
            path: path.into(),
            body: None,
            extra_headers: Vec::new(),
            auth: true,
        }
    }

    fn post(path: impl Into<String>, body: Option<Json>) -> Self {
        RequestSpec {
            method: HttpMethod::Post,
            path: path.into(),
            body,
            extra_headers: Vec::new(),
            auth: true,
        }
    }
}

impl GatewayClient {
    /// `base_url` with trailing slashes removed; `token` may be omitted only
    /// for the operator bootstrap (`create_user`).
    pub fn new(
        base_url: &str,
        token: Option<String>,
        timeout_ms: Option<u64>,
        transport: Arc<dyn HttpTransport>,
    ) -> GatewayClient {
        GatewayClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token,
            timeout_ms: timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
            transport,
        }
    }

    /// Build the request, hand it to the transport and map the response:
    /// 2xx → parsed JSON body (`Null` if empty/non-JSON, as the TS client's
    /// `payload = null`); anything else → `Gateway { status, code, detail }`
    /// from the `{ error: { code, message } }` body when present.
    fn request(&self, spec: RequestSpec<'_>) -> SdkResult<Json> {
        let mut headers: HashMap<String, String> = HashMap::new();
        for (name, value) in spec.extra_headers {
            headers.insert(name.to_owned(), value.to_owned());
        }
        if spec.auth {
            let token = self.token.as_ref().ok_or_else(|| SdkError::Gateway {
                status: 0,
                code: "NO_TOKEN".into(),
                detail: "gateway client has no bearer token configured".into(),
            })?;
            headers.insert("authorization".into(), format!("Bearer {token}"));
        }
        let body = spec.body.map(|json| json.to_json_string());
        if body.is_some() {
            headers.insert("content-type".into(), "application/json".into());
        }
        let request = HttpRequest {
            method: spec.method,
            url: format!("{}{}", self.base_url, spec.path),
            headers,
            body,
            timeout_ms: self.timeout_ms,
        };
        let response = self.transport.send(request)?;
        let payload = json::parse(&response.body).unwrap_or(Json::Null);
        if !(200..300).contains(&response.status) {
            let error = payload.get("error");
            let code = error
                .and_then(|e| e.get("code"))
                .and_then(Json::as_str)
                .unwrap_or("UNKNOWN")
                .to_owned();
            let detail = error
                .and_then(|e| e.get("message"))
                .and_then(Json::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("gateway returned {}", response.status));
            return Err(SdkError::Gateway {
                status: response.status,
                code,
                detail,
            });
        }
        Ok(payload)
    }

    /// Money-moving POST: carries an `Idempotency-Key`, generated unless the
    /// caller pinned one.
    fn post_idempotent(
        &self,
        path: &str,
        body: Json,
        idempotency_key: Option<String>,
    ) -> SdkResult<Json> {
        let key = match idempotency_key {
            Some(key) => key,
            None => generate_idempotency_key()?,
        };
        let mut spec = RequestSpec::post(path, Some(body));
        spec.extra_headers.push(("idempotency-key", key.as_str()));
        self.request(spec)
    }

    /// Bootstrap-only; requires the operator token, not a user token.
    pub fn create_user(&self, operator_token: &str) -> SdkResult<CreatedUser> {
        let mut spec = RequestSpec::post("/v1/users", None);
        spec.auth = false;
        spec.extra_headers
            .push(("x-operator-token", operator_token));
        let v = self.request(spec)?;
        Ok(CreatedUser {
            user_id: field_str(&v, "userId")?,
            token: field_str(&v, "token")?,
            created_at: field_u64(&v, "createdAt")?,
        })
    }

    pub fn me(&self) -> SdkResult<MeInfo> {
        let v = self.request(RequestSpec::get("/v1/me"))?;
        Ok(MeInfo {
            user_id: field_str(&v, "userId")?,
            created_at: field_u64(&v, "createdAt")?,
        })
    }

    /// Register the account xpubs and master fingerprint. This is the only
    /// key-related request the client ever makes, and it carries public
    /// material only.
    pub fn register_xpubs(&self, params: &RegisterXpubsParams) -> SdkResult<RegisteredXpubs> {
        let body = ObjectBuilder::new()
            .field("vanilla", params.vanilla.as_str())
            .field("colored", params.colored.as_str())
            .field("fingerprint", params.fingerprint.as_str())
            .build();
        let v = self.request(RequestSpec::post("/v1/wallet/xpubs", Some(body)))?;
        Ok(RegisteredXpubs {
            fingerprint: field_str(&v, "fingerprint")?,
            address: field_str(&v, "address")?,
        })
    }

    pub fn get_address(&self) -> SdkResult<WalletAddress> {
        let v = self.request(RequestSpec::get("/v1/wallet/address"))?;
        Ok(WalletAddress {
            address: field_str(&v, "address")?,
        })
    }

    pub fn get_balances(&self) -> SdkResult<WalletBalances> {
        let v = self.request(RequestSpec::get("/v1/wallet/balances"))?;
        let btc = field(&v, "btc")?;
        let assets = field_array(&v, "assets")?
            .iter()
            .map(|a| {
                Ok(AssetBalance {
                    asset_id: field_str(a, "assetId")?,
                    schema: field_str(a, "schema")?,
                    ticker: field_opt_str(a, "ticker")?,
                    name: field_str(a, "name")?,
                    precision: u8::try_from(field_u64(a, "precision")?)
                        .map_err(|_| malformed("assets[].precision out of range"))?,
                    balance: parse_balance(field(a, "balance")?)?,
                })
            })
            .collect::<SdkResult<Vec<_>>>()?;
        Ok(WalletBalances {
            btc: BtcBalances {
                vanilla: parse_balance(field(btc, "vanilla")?)?,
                colored: parse_balance(field(btc, "colored")?)?,
            },
            assets,
        })
    }

    pub fn get_unspents(&self) -> SdkResult<WalletUnspents> {
        let v = self.request(RequestSpec::get("/v1/wallet/unspents"))?;
        let unspents = field_array(&v, "unspents")?
            .iter()
            .map(|u| {
                let allocations = field_array(u, "allocations")?
                    .iter()
                    .map(|a| {
                        Ok(UnspentAllocation {
                            asset_id: field_opt_str(a, "assetId")?,
                            amount: field_opt_u64(a, "amount")?,
                            settled: field_bool(a, "settled")?,
                        })
                    })
                    .collect::<SdkResult<Vec<_>>>()?;
                Ok(WalletUnspent {
                    txid: field_str(u, "txid")?,
                    vout: u32::try_from(field_u64(u, "vout")?)
                        .map_err(|_| malformed("unspents[].vout out of range"))?,
                    amount_sat: field_u64(u, "amountSat")?,
                    colorable: field_bool(u, "colorable")?,
                    allocations,
                })
            })
            .collect::<SdkResult<Vec<_>>>()?;
        Ok(WalletUnspents { unspents })
    }

    pub fn get_transfers(&self, asset_id: Option<&str>) -> SdkResult<WalletTransfers> {
        let query = match asset_id {
            Some(id) => format!("?assetId={}", encode_uri_component(id)),
            None => String::new(),
        };
        let v = self.request(RequestSpec::get(format!("/v1/wallet/transfers{query}")))?;
        let transfers = field_array(&v, "transfers")?
            .iter()
            .map(|t| {
                Ok(WalletTransfer {
                    idx: field_u64(t, "idx")?,
                    asset_id: field_opt_str(t, "assetId")?,
                    amount: field_opt_u64(t, "amount")?,
                    kind: field_str(t, "kind")?,
                    status: field_str(t, "status")?,
                    txid: field_opt_str(t, "txid")?,
                    recipient_id: field_opt_str(t, "recipientId")?,
                    expiration: field_opt_u64(t, "expiration")?,
                    created_at: field_u64(t, "createdAt")?,
                    updated_at: field_u64(t, "updatedAt")?,
                })
            })
            .collect::<SdkResult<Vec<_>>>()?;
        Ok(WalletTransfers { transfers })
    }

    pub fn receive(&self, params: &ReceiveParams) -> SdkResult<ReceiveResult> {
        let body = ObjectBuilder::new()
            .field("mode", params.mode.wire())
            .optional("assetId", params.asset_id.clone())
            .optional("amount", params.amount)
            .optional("durationSeconds", params.duration_seconds)
            .optional("minConfirmations", params.min_confirmations)
            .build();
        let v = self.request(RequestSpec::post("/v1/wallet/receive", Some(body)))?;
        let mode = field_str(&v, "mode")?;
        Ok(ReceiveResult {
            invoice: field_str(&v, "invoice")?,
            recipient_id: field_str(&v, "recipientId")?,
            expiration_timestamp: field_opt_u64(&v, "expirationTimestamp")?,
            mode: ReceiveMode::from_wire(&mode)
                .ok_or_else(|| malformed(&format!("unknown receive mode {mode:?}")))?,
        })
    }

    pub fn sync(&self) -> SdkResult<SyncResult> {
        let v = self.request(RequestSpec::post("/v1/wallet/sync", None))?;
        Ok(SyncResult {
            status: field_str(&v, "status")?,
        })
    }

    /// Prepare a BTC send. `IntentMismatch` if the returned intent
    /// contradicts `params` (see `checked_intent`).
    pub fn prepare_send_btc(
        &self,
        params: &PrepareSendBtcParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<PreparedOp> {
        let body = ObjectBuilder::new()
            .field("address", params.address.as_str())
            .field("amountSat", params.amount_sat)
            .optional("feeRateSatPerVb", params.fee_rate_sat_per_vb)
            .build();
        let v = self.post_idempotent("/v1/onchain/send-btc/prepare", body, idempotency_key)?;
        checked_intent(&v, IntentKind::SendBtc, |intent, mismatch| {
            let recipients = intent.recipients;
            if recipients.len() == 1 {
                let only = &recipients[0];
                let address = only.get("address").and_then(Json::as_str);
                if address != Some(params.address.as_str()) {
                    mismatch(format!(
                        "recipient address {} != {}",
                        display(only.get("address")),
                        params.address
                    ));
                }
                let amount = only.get("amountSat").and_then(Json::as_u64);
                if amount != Some(params.amount_sat) {
                    mismatch(format!(
                        "recipient amountSat {} != {}",
                        display(only.get("amountSat")),
                        params.amount_sat
                    ));
                }
            } else {
                mismatch(format!(
                    "expected exactly 1 recipient, got {}",
                    recipients.len()
                ));
            }
            if !intent.asset.is_null() {
                mismatch("send-btc intent carries an asset".into());
            }
            if !intent.utxos.is_null() {
                mismatch("send-btc intent carries a utxo shape".into());
            }
            check_pinned_u64(
                "feeRateSatPerVb",
                params.fee_rate_sat_per_vb,
                intent.fee_rate,
                mismatch,
            );
        })
    }

    pub fn complete_send_btc(
        &self,
        params: &CompleteParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<CompleteResult> {
        let v = self.post_idempotent(
            "/v1/onchain/send-btc/complete",
            complete_body(params),
            idempotency_key,
        )?;
        Ok(CompleteResult {
            txid: field_str(&v, "txid")?,
        })
    }

    /// Prepare an RGB asset send. `IntentMismatch` if the returned intent
    /// contradicts `params` (see `checked_intent`).
    pub fn prepare_send_asset(
        &self,
        params: &PrepareSendAssetParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<PreparedOp> {
        let body = ObjectBuilder::new()
            .field("assetId", params.asset_id.as_str())
            .field("amount", params.amount)
            .field("recipientId", params.recipient_id.as_str())
            .optional("witnessAmountSat", params.witness_amount_sat)
            .optional("transportEndpoints", params.transport_endpoints.clone())
            .optional("donation", params.donation)
            .optional("minConfirmations", params.min_confirmations)
            .optional("feeRateSatPerVb", params.fee_rate_sat_per_vb)
            .build();
        let v = self.post_idempotent("/v1/onchain/send-asset/prepare", body, idempotency_key)?;
        checked_intent(&v, IntentKind::SendAsset, |intent, mismatch| {
            if !intent.recipients.is_empty() {
                mismatch(format!(
                    "send-asset intent carries {} bitcoin recipient(s)",
                    intent.recipients.len()
                ));
            }
            if !intent.utxos.is_null() {
                mismatch("send-asset intent carries a utxo shape".into());
            }
            let asset = intent.asset;
            if asset.as_object().is_none() {
                mismatch("send-asset intent carries no asset".into());
                return;
            }
            if asset.get("assetId").and_then(Json::as_str) != Some(params.asset_id.as_str()) {
                mismatch(format!(
                    "assetId {} != {}",
                    display(asset.get("assetId")),
                    params.asset_id
                ));
            }
            if asset.get("amount").and_then(Json::as_u64) != Some(params.amount) {
                mismatch(format!(
                    "amount {} != {}",
                    display(asset.get("amount")),
                    params.amount
                ));
            }
            if asset.get("recipientId").and_then(Json::as_str) != Some(params.recipient_id.as_str())
            {
                mismatch(format!(
                    "recipientId {} != {}",
                    display(asset.get("recipientId")),
                    params.recipient_id
                ));
            }
            // Always asserted, including the blind case: a witness amount the
            // caller never asked for lets check 2 account for one foreign
            // output of that size, which check 3 would otherwise have refused.
            // A missing field is a mismatch too (`undefined !== null`).
            let witness_ok = match (asset.get("witnessAmountSat"), params.witness_amount_sat) {
                (Some(v), None) => v.is_null(),
                (Some(v), Some(expected)) => v.as_u64() == Some(expected),
                (None, _) => false,
            };
            if !witness_ok {
                mismatch(format!(
                    "witnessAmountSat {} != {}",
                    display(asset.get("witnessAmountSat")),
                    params
                        .witness_amount_sat
                        .map_or_else(|| "null".to_owned(), |v| v.to_string())
                ));
            }
            if let Some(endpoints) = &params.transport_endpoints {
                let returned: Option<Vec<&str>> = asset
                    .get("transportEndpoints")
                    .and_then(Json::as_array)
                    .map(|items| items.iter().filter_map(Json::as_str).collect());
                let same = returned.as_ref().is_some_and(|r| {
                    r.len() == endpoints.len() && r.iter().zip(endpoints).all(|(a, b)| a == b)
                });
                if !same {
                    mismatch(format!(
                        "transportEndpoints {} != {}",
                        returned.map_or_else(|| "null".to_owned(), |r| r.join(",")),
                        endpoints.join(",")
                    ));
                }
            }
            check_pinned_u64(
                "feeRateSatPerVb",
                params.fee_rate_sat_per_vb,
                intent.fee_rate,
                mismatch,
            );
        })
    }

    pub fn complete_send_asset(
        &self,
        params: &CompleteParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<CompleteResult> {
        let v = self.post_idempotent(
            "/v1/onchain/send-asset/complete",
            complete_body(params),
            idempotency_key,
        )?;
        Ok(CompleteResult {
            txid: field_str(&v, "txid")?,
        })
    }

    /// Prepare a UTXO-creation transaction. `IntentMismatch` if the returned
    /// intent contradicts `params` (see `checked_intent`).
    pub fn prepare_create_utxos(
        &self,
        params: &PrepareCreateUtxosParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<PreparedOp> {
        let body = ObjectBuilder::new()
            .optional("num", params.num)
            .optional("size", params.size)
            .optional("upTo", params.up_to)
            .optional("feeRateSatPerVb", params.fee_rate_sat_per_vb)
            .build();
        let v = self.post_idempotent("/v1/onchain/create-utxos/prepare", body, idempotency_key)?;
        checked_intent(&v, IntentKind::CreateUtxos, |intent, mismatch| {
            if !intent.recipients.is_empty() {
                mismatch(format!(
                    "create-utxos intent carries {} recipient(s)",
                    intent.recipients.len()
                ));
            }
            if !intent.asset.is_null() {
                mismatch("create-utxos intent carries an asset".into());
            }
            let utxos = intent.utxos;
            if utxos.as_object().is_none() {
                mismatch("create-utxos intent carries no utxo shape".into());
                return;
            }
            check_pinned_u64("num", params.num.map(u64::from), utxos.get("num"), mismatch);
            check_pinned_u64("size", params.size, utxos.get("size"), mismatch);
            if let Some(up_to) = params.up_to {
                if utxos.get("upTo").and_then(Json::as_bool) != Some(up_to) {
                    mismatch(format!("upTo {} != {up_to}", display(utxos.get("upTo"))));
                }
            }
            check_pinned_u64(
                "feeRateSatPerVb",
                params.fee_rate_sat_per_vb,
                intent.fee_rate,
                mismatch,
            );
        })
    }

    pub fn complete_create_utxos(
        &self,
        params: &CompleteParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<CreateUtxosCompleteResult> {
        let v = self.post_idempotent(
            "/v1/onchain/create-utxos/complete",
            complete_body(params),
            idempotency_key,
        )?;
        Ok(CreateUtxosCompleteResult {
            txid: field_opt_str(&v, "txid")?,
            utxos_created: u32::try_from(field_u64(&v, "utxosCreated")?)
                .map_err(|_| malformed("utxosCreated out of range"))?,
        })
    }

    /// Read back a prepared operation's durable state.
    ///
    /// Safe to poll: a read, no idempotency key, and the gateway does not queue
    /// it behind that user's wallet work — so it answers even while the
    /// `complete` being asked about is still running. It never returns the
    /// PSBT; the caller already holds it from `prepare`.
    pub fn get_onchain_operation(&self, op_id: &str) -> SdkResult<OperationStatus> {
        let v = self.request(RequestSpec::get(format!(
            "/v1/onchain/operations/{}",
            encode_uri_component(op_id)
        )))?;
        let state_wire = field_str(&v, "state")?;
        let state = OperationState::from_wire(&state_wire)
            .ok_or_else(|| malformed(&format!("unknown operation state {state_wire:?}")))?;
        let kind_wire = field_str(&v, "kind")?;
        let kind = IntentKind::from_wire(&kind_wire)
            .ok_or_else(|| malformed(&format!("unknown operation kind {kind_wire:?}")))?;
        let intent = v
            .get("intent")
            .ok_or_else(|| malformed("operation carries no intent summary"))?;
        // Reuse the same typed decoder `prepare` uses, so a field this SDK
        // cannot represent fails here rather than surfacing as a silent default.
        let intent = typed_intent(intent, kind).map_err(|e| malformed(&e))?;
        Ok(OperationStatus {
            op_id: field_str(&v, "opId")?,
            kind,
            state,
            txid: field_opt_str(&v, "txid")?,
            may_have_broadcast: v
                .get("mayHaveBroadcast")
                .and_then(Json::as_bool)
                .ok_or_else(|| malformed("mayHaveBroadcast is not a boolean"))?,
            intent,
            created_at: field_u64(&v, "createdAt")?,
            expires_at: field_u64(&v, "expiresAt")?,
        })
    }

    /// Pin the idempotency key to retry a prepare without minting a second
    /// deposit target.
    pub fn prepare_ln_deposit(
        &self,
        params: &LnDepositPrepareParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<LnDepositPrepareResult> {
        let body = ObjectBuilder::new()
            .field("kind", params.kind.wire())
            .optional("amountMsat", params.amount_msat)
            .optional("assetId", params.asset_id.clone())
            .optional("amount", params.amount)
            .build();
        let v = self.post_idempotent("/v1/ln/deposit/prepare", body, idempotency_key)?;
        let kind = field_str(&v, "kind")?;
        Ok(LnDepositPrepareResult {
            deposit_id: field_str(&v, "depositId")?,
            kind: LnAssetKind::from_wire(&kind)
                .ok_or_else(|| malformed(&format!("unknown deposit kind {kind:?}")))?,
            address: field_opt_str(&v, "address")?,
            invoice: field_opt_str(&v, "invoice")?,
            recipient_id: field_opt_str(&v, "recipientId")?,
        })
    }

    /// Money-moving: pin the idempotency key to retry the SAME payment safely.
    pub fn pay_ln_invoice(
        &self,
        params: &LnPayParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<LnPayResult> {
        let body = ObjectBuilder::new()
            .field("invoice", params.invoice.as_str())
            .optional("amtMsat", params.amt_msat)
            .optional("assetAmount", params.asset_amount)
            .build();
        let v = self.post_idempotent("/v1/ln/pay", body, idempotency_key)?;
        let status = field_str(&v, "status")?;
        Ok(LnPayResult {
            payment_hash: field_str(&v, "paymentHash")?,
            status: LnPaymentStatus::from_wire(&status)
                .ok_or_else(|| malformed(&format!("unknown payment status {status:?}")))?,
        })
    }

    pub fn create_ln_invoice(&self, params: &LnInvoiceCreateParams) -> SdkResult<LnInvoiceCreated> {
        let body = ObjectBuilder::new()
            .optional("amtMsat", params.amt_msat)
            .optional("expirySec", params.expiry_sec)
            .optional("assetId", params.asset_id.clone())
            .optional("assetAmount", params.asset_amount)
            .optional("description", params.description.clone())
            .build();
        let v = self.request(RequestSpec::post("/v1/ln/invoice", Some(body)))?;
        Ok(LnInvoiceCreated {
            invoice: field_str(&v, "invoice")?,
            payment_hash: field_str(&v, "paymentHash")?,
        })
    }

    pub fn get_ln_invoice(&self, payment_hash: &str) -> SdkResult<LnInvoiceInfo> {
        let v = self.request(RequestSpec::get(format!(
            "/v1/ln/invoice/{}",
            encode_uri_component(payment_hash)
        )))?;
        let state = field_str(&v, "state")?;
        Ok(LnInvoiceInfo {
            payment_hash: field_str(&v, "paymentHash")?,
            invoice: field_str(&v, "invoice")?,
            state: LnInvoiceState::from_wire(&state)
                .ok_or_else(|| malformed(&format!("unknown invoice state {state:?}")))?,
            amt_msat: field_opt_u64(&v, "amtMsat")?,
            asset_id: field_opt_str(&v, "assetId")?,
            asset_amount: field_opt_u64(&v, "assetAmount")?,
            created_at: field_u64(&v, "createdAt")?,
        })
    }

    pub fn list_ln_payments(&self) -> SdkResult<LnPayments> {
        let v = self.request(RequestSpec::get("/v1/ln/payments"))?;
        let payments = field_array(&v, "payments")?
            .iter()
            .map(|p| {
                let direction = field_str(p, "direction")?;
                let status = field_str(p, "status")?;
                Ok(LnPaymentEntry {
                    payment_hash: field_str(p, "paymentHash")?,
                    direction: LnPaymentDirection::from_wire(&direction).ok_or_else(|| {
                        malformed(&format!("unknown payment direction {direction:?}"))
                    })?,
                    status: LnPaymentStatus::from_wire(&status)
                        .ok_or_else(|| malformed(&format!("unknown payment status {status:?}")))?,
                    amt_msat: field_opt_u64(p, "amtMsat")?,
                    asset_id: field_opt_str(p, "assetId")?,
                    asset_amount: field_opt_u64(p, "assetAmount")?,
                    created_at: field_u64(p, "createdAt")?,
                    updated_at: field_u64(p, "updatedAt")?,
                })
            })
            .collect::<SdkResult<Vec<_>>>()?;
        Ok(LnPayments { payments })
    }

    pub fn get_ln_balance(&self) -> SdkResult<LnBalance> {
        let v = self.request(RequestSpec::get("/v1/ln/balance"))?;
        let assets = field(&v, "assets")?
            .as_object()
            .ok_or_else(|| malformed("assets is not an object"))?
            .iter()
            .map(|(id, amount)| {
                let amount = amount
                    .as_u64()
                    .ok_or_else(|| malformed(&format!("assets[{id:?}] is not an integer")))?;
                Ok((id.clone(), amount))
            })
            .collect::<SdkResult<HashMap<_, _>>>()?;
        Ok(LnBalance {
            btc_msat: field_u64(&v, "btcMsat")?,
            assets,
        })
    }

    /// Money-moving: pin the idempotency key to retry the SAME withdrawal.
    pub fn withdraw_ln(
        &self,
        params: &LnWithdrawParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<LnWithdrawResult> {
        let body = ObjectBuilder::new()
            .field("kind", params.kind.wire())
            .optional("address", params.address.clone())
            .optional("amountSat", params.amount_sat)
            .optional("assetId", params.asset_id.clone())
            .optional("amount", params.amount)
            .optional("recipientId", params.recipient_id.clone())
            .optional("witnessAmountSat", params.witness_amount_sat)
            .optional("transportEndpoints", params.transport_endpoints.clone())
            .optional("feeRateSatPerVb", params.fee_rate_sat_per_vb)
            .build();
        let v = self.post_idempotent("/v1/ln/withdraw", body, idempotency_key)?;
        Ok(LnWithdrawResult {
            withdrawal_id: field_str(&v, "withdrawalId")?,
            txid: field_str(&v, "txid")?,
        })
    }
}

fn complete_body(params: &CompleteParams) -> Json {
    ObjectBuilder::new()
        .field("opId", params.op_id.as_str())
        .field("signedPsbt", params.signed_psbt.as_str())
        .build()
}

// ---------------------------------------------------------------------------
// Intent binding
// ---------------------------------------------------------------------------

/// The server's intent, still untyped, as handed to the per-kind comparison.
struct RawIntent<'a> {
    recipients: &'a [Json],
    asset: &'a Json,
    utxos: &'a Json,
    fee_rate: Option<&'a Json>,
}

/// Bind the gateway's intent summary to the caller's OWN request.
///
/// `verify` check 2 matches the PSBT's outputs against the intent. If that
/// intent is simply whatever the server chose to return, the check is
/// vacuous against the threat verify-before-sign exists for: a hostile
/// gateway pairs an attacker script in the PSBT with the same attacker
/// address in the intent and both "match", while checks 1/3/4/5 stay clean
/// (the output is accounted, so change-own skips it). The design doc calls
/// for the *user's* stated intent (`minimal-sdk-and-lightweight-rln.md`,
/// check 2), so every field the caller actually stated is asserted here
/// before the intent is handed on.
///
/// Fields the caller left to the server (fee rate, transport endpoints, utxo
/// shape) are asserted only when the caller pinned them: they carry no
/// bitcoin value for check 2, and the absolute fee stays bounded by
/// `max_fee_sat`. The shape assertions (no recipients on an asset/utxo
/// intent, no asset on a send-btc intent) are not cosmetic — a foreign
/// `asset.witnessAmountSat` or an extra recipient is exactly how a server
/// would smuggle an unaccounted output past check 3.
///
/// The comparison runs on the **untyped** JSON so that a malformed field is
/// reported as a mismatch (fail closed) rather than silently coerced; the
/// typed [`OnchainIntent`] is built only after every assertion passed, and
/// any field it cannot represent is a mismatch too. All mismatches are
/// collected and returned together as one `IntentMismatch`.
fn checked_intent(
    prepared: &Json,
    kind: IntentKind,
    compare: impl FnOnce(RawIntent<'_>, &mut dyn FnMut(String)),
) -> SdkResult<PreparedOp> {
    let intent = match prepared.get("intent") {
        Some(intent) if intent.as_object().is_some() => intent,
        _ => {
            return Err(SdkError::IntentMismatch {
                reason: "prepare response carries no intent summary".into(),
            })
        }
    };
    let mut mismatches: Vec<String> = Vec::new();
    let returned_kind = intent.get("kind").and_then(Json::as_str);
    if returned_kind != Some(kind.name()) {
        mismatches.push(format!(
            "kind {} != {kind}",
            returned_kind.unwrap_or("undefined")
        ));
    }
    match intent.get("recipients").and_then(Json::as_array) {
        None => mismatches.push("intent.recipients is not an array".into()),
        Some(recipients) => {
            let null = Json::Null;
            let raw = RawIntent {
                recipients,
                asset: intent.get("asset").unwrap_or(&null),
                utxos: intent.get("utxos").unwrap_or(&null),
                fee_rate: intent.get("feeRateSatPerVb"),
            };
            compare(raw, &mut |detail| mismatches.push(detail));
        }
    }
    let mismatch_error = |mismatches: &[String]| SdkError::IntentMismatch {
        reason: format!(
            "gateway intent does not match the request: {}",
            mismatches.join("; ")
        ),
    };
    if !mismatches.is_empty() {
        return Err(mismatch_error(&mismatches));
    }
    let intent = typed_intent(intent, kind).map_err(|detail| mismatch_error(&[detail]))?;
    Ok(PreparedOp {
        op_id: field_str(prepared, "opId")?,
        psbt: field_str(prepared, "psbt")?,
        intent,
        expires_at: field_u64(prepared, "expiresAt")?,
    })
}

/// Convert the (already compared) server intent into the typed record
/// `verify` consumes. Any field that does not fit is reported by name.
fn typed_intent(intent: &Json, kind: IntentKind) -> Result<OnchainIntent, String> {
    let fee_rate_sat_per_vb = intent
        .get("feeRateSatPerVb")
        .and_then(Json::as_u64)
        .ok_or("intent.feeRateSatPerVb is not an integer")?;
    let recipients = intent
        .get("recipients")
        .and_then(Json::as_array)
        .ok_or("intent.recipients is not an array")?
        .iter()
        .map(|r| {
            Ok(IntentRecipient {
                address: r
                    .get("address")
                    .and_then(Json::as_str)
                    .ok_or("recipient.address is not a string")?
                    .to_owned(),
                script_hex: r
                    .get("scriptHex")
                    .and_then(Json::as_str)
                    .ok_or("recipient.scriptHex is not a string")?
                    .to_owned(),
                amount_sat: r
                    .get("amountSat")
                    .and_then(Json::as_u64)
                    .ok_or("recipient.amountSat is not an integer")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let asset = match intent.get("asset") {
        None | Some(Json::Null) => None,
        Some(a) => {
            let witness = match a.get("witnessAmountSat") {
                None | Some(Json::Null) => None,
                Some(v) => Some(
                    v.as_u64()
                        .ok_or("asset.witnessAmountSat is not an integer")?,
                ),
            };
            let transport_endpoints = a
                .get("transportEndpoints")
                .and_then(Json::as_array)
                .ok_or("asset.transportEndpoints is not an array")?
                .iter()
                .map(|e| {
                    e.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "asset.transportEndpoints[] is not a string".to_owned())
                })
                .collect::<Result<Vec<_>, String>>()?;
            Some(IntentAsset {
                asset_id: a
                    .get("assetId")
                    .and_then(Json::as_str)
                    .ok_or("asset.assetId is not a string")?
                    .to_owned(),
                amount: a
                    .get("amount")
                    .and_then(Json::as_u64)
                    .ok_or("asset.amount is not an integer")?,
                recipient_id: a
                    .get("recipientId")
                    .and_then(Json::as_str)
                    .ok_or("asset.recipientId is not a string")?
                    .to_owned(),
                witness_amount_sat: witness,
                transport_endpoints,
            })
        }
    };
    let utxos = match intent.get("utxos") {
        None | Some(Json::Null) => None,
        Some(u) => Some(IntentUtxos {
            up_to: u
                .get("upTo")
                .and_then(Json::as_bool)
                .ok_or("utxos.upTo is not a boolean")?,
            num: u
                .get("num")
                .and_then(Json::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or("utxos.num is not a u32")?,
            size: u
                .get("size")
                .and_then(Json::as_u64)
                .ok_or("utxos.size is not an integer")?,
        }),
    };
    Ok(OnchainIntent {
        kind,
        fee_rate_sat_per_vb,
        recipients,
        asset,
        utxos,
    })
}

/// `checkPinned`: a caller-pinned integer must come back exactly.
fn check_pinned_u64(
    name: &str,
    requested: Option<u64>,
    returned: Option<&Json>,
    mismatch: &mut dyn FnMut(String),
) {
    if let Some(expected) = requested {
        if returned.and_then(Json::as_u64) != Some(expected) {
            mismatch(format!("{name} {} != {expected}", display(returned)));
        }
    }
}

/// Render a JSON scalar for a mismatch message (`String(x)` in TS).
fn display(value: Option<&Json>) -> String {
    match value {
        None => "undefined".into(),
        Some(Json::Null) => "null".into(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(Json::Number(n)) => n.clone(),
        Some(Json::String(s)) => s.clone(),
        Some(other) => other.to_json_string(),
    }
}

// ---------------------------------------------------------------------------
// Response field access
// ---------------------------------------------------------------------------

/// A 2xx body that does not have the documented shape.
fn malformed(detail: &str) -> SdkError {
    SdkError::Gateway {
        status: 0,
        code: "MALFORMED_RESPONSE".into(),
        detail: format!("gateway response malformed: {detail}"),
    }
}

fn field<'a>(v: &'a Json, key: &str) -> SdkResult<&'a Json> {
    v.get(key)
        .ok_or_else(|| malformed(&format!("missing field {key}")))
}

fn field_str(v: &Json, key: &str) -> SdkResult<String> {
    field(v, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| malformed(&format!("{key} is not a string")))
}

fn field_opt_str(v: &Json, key: &str) -> SdkResult<Option<String>> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(malformed(&format!("{key} is not a string or null"))),
    }
}

fn field_u64(v: &Json, key: &str) -> SdkResult<u64> {
    field(v, key)?
        .as_u64()
        .ok_or_else(|| malformed(&format!("{key} is not a non-negative integer")))
}

fn field_opt_u64(v: &Json, key: &str) -> SdkResult<Option<u64>> {
    match v.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(n) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| malformed(&format!("{key} is not an integer or null"))),
    }
}

fn field_bool(v: &Json, key: &str) -> SdkResult<bool> {
    field(v, key)?
        .as_bool()
        .ok_or_else(|| malformed(&format!("{key} is not a boolean")))
}

fn field_array<'a>(v: &'a Json, key: &str) -> SdkResult<&'a [Json]> {
    field(v, key)?
        .as_array()
        .ok_or_else(|| malformed(&format!("{key} is not an array")))
}

fn parse_balance(v: &Json) -> SdkResult<Balance> {
    Ok(Balance {
        settled: field_u64(v, "settled")?,
        future: field_u64(v, "future")?,
        spendable: field_u64(v, "spendable")?,
    })
}

// ---------------------------------------------------------------------------
// uniffi surface
// ---------------------------------------------------------------------------

/// The uniffi surface of [`GatewayClient`]: one method per gateway route.
/// `idempotency_key` may be `null` (a fresh v4 UUID is generated) or pinned
/// by the caller to retry the same operation safely.
#[uniffi::export]
impl GatewayClient {
    /// `base_url` like `https://gw.example.com` (trailing slashes ignored),
    /// the user's bearer token (`null` only for `create_user`), an optional
    /// timeout in milliseconds (default 30 000) and the host transport.
    #[uniffi::constructor(name = "new")]
    pub fn ffi_new(
        base_url: String,
        token: Option<String>,
        timeout_ms: Option<u64>,
        transport: Arc<dyn HttpTransport>,
    ) -> Arc<Self> {
        Arc::new(Self::new(&base_url, token, timeout_ms, transport))
    }

    #[uniffi::method(name = "create_user")]
    pub fn ffi_create_user(&self, operator_token: String) -> SdkResult<CreatedUser> {
        self.create_user(&operator_token)
    }

    #[uniffi::method(name = "me")]
    pub fn ffi_me(&self) -> SdkResult<MeInfo> {
        self.me()
    }

    #[uniffi::method(name = "register_xpubs")]
    pub fn ffi_register_xpubs(&self, params: RegisterXpubsParams) -> SdkResult<RegisteredXpubs> {
        self.register_xpubs(&params)
    }

    #[uniffi::method(name = "get_address")]
    pub fn ffi_get_address(&self) -> SdkResult<WalletAddress> {
        self.get_address()
    }

    #[uniffi::method(name = "get_balances")]
    pub fn ffi_get_balances(&self) -> SdkResult<WalletBalances> {
        self.get_balances()
    }

    #[uniffi::method(name = "get_unspents")]
    pub fn ffi_get_unspents(&self) -> SdkResult<WalletUnspents> {
        self.get_unspents()
    }

    #[uniffi::method(name = "get_transfers")]
    pub fn ffi_get_transfers(&self, asset_id: Option<String>) -> SdkResult<WalletTransfers> {
        self.get_transfers(asset_id.as_deref())
    }

    #[uniffi::method(name = "receive")]
    pub fn ffi_receive(&self, params: ReceiveParams) -> SdkResult<ReceiveResult> {
        self.receive(&params)
    }

    #[uniffi::method(name = "sync")]
    pub fn ffi_sync(&self) -> SdkResult<SyncResult> {
        self.sync()
    }

    #[uniffi::method(name = "prepare_send_btc")]
    pub fn ffi_prepare_send_btc(
        &self,
        params: PrepareSendBtcParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<PreparedOp> {
        self.prepare_send_btc(&params, idempotency_key)
    }

    #[uniffi::method(name = "complete_send_btc")]
    pub fn ffi_complete_send_btc(
        &self,
        params: CompleteParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<CompleteResult> {
        self.complete_send_btc(&params, idempotency_key)
    }

    #[uniffi::method(name = "prepare_send_asset")]
    pub fn ffi_prepare_send_asset(
        &self,
        params: PrepareSendAssetParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<PreparedOp> {
        self.prepare_send_asset(&params, idempotency_key)
    }

    #[uniffi::method(name = "complete_send_asset")]
    pub fn ffi_complete_send_asset(
        &self,
        params: CompleteParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<CompleteResult> {
        self.complete_send_asset(&params, idempotency_key)
    }

    #[uniffi::method(name = "prepare_create_utxos")]
    pub fn ffi_prepare_create_utxos(
        &self,
        params: PrepareCreateUtxosParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<PreparedOp> {
        self.prepare_create_utxos(&params, idempotency_key)
    }

    #[uniffi::method(name = "complete_create_utxos")]
    pub fn ffi_complete_create_utxos(
        &self,
        params: CompleteParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<CreateUtxosCompleteResult> {
        self.complete_create_utxos(&params, idempotency_key)
    }

    #[uniffi::method(name = "get_onchain_operation")]
    pub fn ffi_get_onchain_operation(&self, op_id: String) -> SdkResult<OperationStatus> {
        self.get_onchain_operation(&op_id)
    }

    #[uniffi::method(name = "prepare_ln_deposit")]
    pub fn ffi_prepare_ln_deposit(
        &self,
        params: LnDepositPrepareParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<LnDepositPrepareResult> {
        self.prepare_ln_deposit(&params, idempotency_key)
    }

    #[uniffi::method(name = "pay_ln_invoice")]
    pub fn ffi_pay_ln_invoice(
        &self,
        params: LnPayParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<LnPayResult> {
        self.pay_ln_invoice(&params, idempotency_key)
    }

    #[uniffi::method(name = "create_ln_invoice")]
    pub fn ffi_create_ln_invoice(
        &self,
        params: LnInvoiceCreateParams,
    ) -> SdkResult<LnInvoiceCreated> {
        self.create_ln_invoice(&params)
    }

    #[uniffi::method(name = "get_ln_invoice")]
    pub fn ffi_get_ln_invoice(&self, payment_hash: String) -> SdkResult<LnInvoiceInfo> {
        self.get_ln_invoice(&payment_hash)
    }

    #[uniffi::method(name = "list_ln_payments")]
    pub fn ffi_list_ln_payments(&self) -> SdkResult<LnPayments> {
        self.list_ln_payments()
    }

    #[uniffi::method(name = "get_ln_balance")]
    pub fn ffi_get_ln_balance(&self) -> SdkResult<LnBalance> {
        self.get_ln_balance()
    }

    #[uniffi::method(name = "withdraw_ln")]
    pub fn ffi_withdraw_ln(
        &self,
        params: LnWithdrawParams,
        idempotency_key: Option<String>,
    ) -> SdkResult<LnWithdrawResult> {
        self.withdraw_ln(&params, idempotency_key)
    }
}

/// Fresh RFC-4122 v4 idempotency key, for callers that want to pin one
/// across a retry loop.
#[uniffi::export(name = "generate_idempotency_key")]
pub fn ffi_generate_idempotency_key() -> SdkResult<String> {
    generate_idempotency_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_keys_are_v4_uuids() {
        let key = generate_idempotency_key().unwrap();
        assert_eq!(key.len(), 36);
        let parts: Vec<&str> = key.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'));
        assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
        assert!(key.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()));
    }

    #[test]
    fn encode_uri_component_matches_javascript() {
        assert_eq!(encode_uri_component("rgb:abc-123"), "rgb%3Aabc-123");
        assert_eq!(
            encode_uri_component("../v1/ln/balance"),
            "..%2Fv1%2Fln%2Fbalance"
        );
        assert_eq!(encode_uri_component("a b&c=d?e#f"), "a%20b%26c%3Dd%3Fe%23f");
        assert_eq!(encode_uri_component("-_.!~*'()"), "-_.!~*'()");
        assert_eq!(encode_uri_component("é"), "%C3%A9");
    }

    #[test]
    fn request_debug_redacts_credentials() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_owned(), "Bearer sekrit".to_owned());
        headers.insert("x-operator-token".to_owned(), "op-sekrit".to_owned());
        headers.insert("idempotency-key".to_owned(), "k".to_owned());
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: "http://gw/v1/x".into(),
            headers,
            body: None,
            timeout_ms: 1,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("sekrit"), "{rendered}");
        assert!(rendered.contains("authorization"));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("\"k\""));
    }

    #[test]
    fn created_user_debug_redacts_the_token() {
        let created = CreatedUser {
            user_id: "u".into(),
            token: "tok-sekrit".into(),
            created_at: 1,
        };
        let rendered = format!("{created:?}");
        assert!(!rendered.contains("sekrit"), "{rendered}");
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("\"u\""));
    }
}
