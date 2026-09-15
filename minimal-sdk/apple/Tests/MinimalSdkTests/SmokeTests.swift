import Foundation
import XCTest
@testable import MinimalSdk
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Smoke test through the generated uniffi bindings.
///
/// Deep assertions (parity for every network and index, the adversarial
/// verify suite, secrets hygiene) live in the Rust crate's `tests/parity.rs`.
/// This test proves the binding surface, the static link and the
/// `with_foreign` `HttpTransport` trait work end to end, against the same
/// rgb-lib-authored fixture the Rust suite reads, by relative path. It is the
/// Swift twin of the Kotlin `SmokeTest`.
final class SmokeTests: XCTestCase {
    // MARK: fixture

    private struct FixtureError: Error, CustomStringConvertible {
        let description: String
    }

    /// Loaded once; a missing or malformed fixture fails each test that
    /// needs it (via `throw`) instead of aborting the whole test process.
    private static let fixtureResult: Result<[String: Any], Error> = {
        let testFile = URL(fileURLWithPath: #filePath)
        let path = ProcessInfo.processInfo.environment["UTEXO_MINIMALSDK_FIXTURE"].map { URL(fileURLWithPath: $0) }
            ?? testFile
                .deletingLastPathComponent()  // MinimalSdkTests
                .deletingLastPathComponent()  // Tests
                .deletingLastPathComponent()  // apple
                .deletingLastPathComponent()  // minimal-sdk
                .appendingPathComponent("packages/client-sdk/test/fixtures/rgblib-parity.json")
        guard let data = FileManager.default.contents(atPath: path.path) else {
            return .failure(FixtureError(description: "parity fixture missing at \(path.path)"))
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .failure(FixtureError(description: "parity fixture is not a JSON object"))
        }
        return .success(json)
    }()

    private func fixture() throws -> [String: Any] { try Self.fixtureResult.get() }

    private func string(_ key: String, in object: [String: Any]) throws -> String {
        guard let value = object[key] as? String else {
            throw FixtureError(description: "fixture key \(key) missing or not a string")
        }
        return value
    }

    private func object(_ key: String, in object: [String: Any]) throws -> [String: Any] {
        guard let value = object[key] as? [String: Any] else {
            throw FixtureError(description: "fixture key \(key) missing or not an object")
        }
        return value
    }

    private func regtestNetworkFixture() throws -> [String: Any] {
        try object("Regtest", in: object("networks", in: fixture()))
    }

    private func regtestAddresses() throws -> [String: Any] { try object("regtest", in: fixture()) }

    private func signingFixture() throws -> [String: Any] { try object("signing", in: fixture()) }

    private func ourKeys() throws -> ClientKeys {
        try ClientKeys.fromMnemonic(mnemonic: string("mnemonic", in: fixture()), network: .regtest)
    }

    private func foreignKeys() throws -> ClientKeys {
        try ClientKeys.fromMnemonic(mnemonic: string("otherMnemonic", in: fixture()), network: .regtest)
    }

    /// The intent the fixture PSBT was prepared for: 40 000 sat to the
    /// foreign wallet's vanilla address 0.
    private func fixtureSendBtcIntent() throws -> OnchainIntent {
        let foreign = try deriveTaprootAddress(
            accountXpub: try foreignKeys().xpubs().vanilla, keychain: 0, index: 0, network: .regtest)
        return OnchainIntent(
            kind: .sendBtc,
            feeRateSatPerVb: 2,
            recipients: [
                IntentRecipient(address: foreign.address, scriptHex: foreign.scriptHex, amountSat: 40_000),
            ],
            asset: nil,
            utxos: nil)
    }

    private func fixtureParams(keys: ClientKeys, intent: OnchainIntent? = nil) throws -> VerifyParams {
        VerifyParams(
            intent: try intent ?? fixtureSendBtcIntent(),
            xpubs: keys.xpubs(),
            maxFeeSat: 2_000,
            changeScanWindow: nil,
            maxOwnOutputIndex: nil)
    }

    // MARK: constants shared with the Kotlin smoke test

    /// BOLT-11 spec vector: 2 500 µBTC, "1 cup coffee", 60 s expiry.
    private static let bolt11Coffee =
        "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh"
    private static let address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
    private static let attacker = "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
    private static let gateway = "https://gateway.example"
    private static let token = "secret-token"
    private static let preparedSendBtc =
        #"{"opId":"op-1","psbt":"cHNidP8=","expiresAt":1700000000,"intent":{"kind":"send_btc","feeRateSatPerVb":2,"# +
        #""recipients":[{"address":"\#(address)","scriptHex":"0014deadbeef","amountSat":40000}],"asset":null,"utxos":null}}"#

    // MARK: tests

    func testNativeLibraryLoadsAndReportsVersion() {
        let version = sdkVersion()
        XCTAssertFalse(version.isEmpty)
        XCTAssertNotNil(version.range(of: #"^\d+\.\d+\.\d+$"#, options: .regularExpression), "semver expected, got \(version)")
    }

    func testRestoreFromFixtureMnemonicMatchesRgbLibXpubsAndFingerprint() throws {
        let keys = try ourKeys()
        let expected = try regtestNetworkFixture()
        XCTAssertEqual(keys.network(), .regtest)
        XCTAssertEqual(keys.fingerprint(), try string("masterFingerprint", in: expected))

        let xpubs = keys.xpubs()
        XCTAssertEqual(xpubs.network, .regtest)
        XCTAssertEqual(xpubs.fingerprint, try string("masterFingerprint", in: expected))
        XCTAssertEqual(xpubs.vanilla, try string("accountXpubVanilla", in: expected))
        XCTAssertEqual(xpubs.colored, try string("accountXpubColored", in: expected))
        // Public material only crosses the boundary.
        XCTAssertFalse(xpubs.vanilla.hasPrefix("tprv") || xpubs.colored.hasPrefix("tprv"))
    }

    func testGeneratedKeysRestoreToTheSameXpubs() throws {
        let generated = try generateKeys(network: .regtest)
        XCTAssertEqual(generated.mnemonic.split(separator: " ").count, 12)
        let restored = try ClientKeys.fromMnemonic(mnemonic: generated.mnemonic, network: .regtest)
        XCTAssertEqual(generated.keys.xpubs(), restored.xpubs())
        XCTAssertEqual(generated.keys.fingerprint(), restored.fingerprint())
        XCTAssertEqual(generated.keys.network(), .regtest)
        XCTAssertTrue(generated.keys.xpubs().vanilla.hasPrefix("tpub"))
        // A fresh generation is a different wallet.
        XCTAssertNotEqual(try generateKeys(network: .regtest).keys.xpubs(), generated.keys.xpubs())
    }

    func testDeriveIndexZeroMatchesRgbLibAddresses() throws {
        let xpubs = try ourKeys().xpubs()
        let addresses = try regtestAddresses()
        let vanillaAddresses = addresses["vanillaAddresses"] as? [String] ?? []
        let coloredAddresses = addresses["coloredAddresses"] as? [String] ?? []

        let vanilla = try deriveTaprootAddress(accountXpub: xpubs.vanilla, keychain: 0, index: 0, network: .regtest)
        XCTAssertEqual(vanilla.address, vanillaAddresses.first)
        XCTAssertEqual(vanilla.keychain, 0)
        XCTAssertEqual(vanilla.index, 0)
        XCTAssertTrue(vanilla.scriptHex.hasPrefix("5120") && vanilla.scriptHex.count == 68)

        let colored = try deriveTaprootAddress(accountXpub: xpubs.colored, keychain: 0, index: 0, network: .regtest)
        XCTAssertEqual(colored.address, coloredAddresses.first)
    }

    func testVerifyAndSignFixturePsbtReachesRgbLibTxid() throws {
        let keys = try ourKeys()
        let signing = try signingFixture()
        let unsigned = try string("unsignedPsbt", in: signing)
        let params = try fixtureParams(keys: keys)

        let verdict = verifyPsbt(psbt: unsigned, params: params)
        XCTAssertTrue(verdict.ok, "verdict failed: \(verdict.checks.filter { !$0.ok })")
        XCTAssertEqual(verdict.checks.count, 5)

        let result = try verifyAndSignPsbt(keys: keys, psbt: unsigned, params: params)
        XCTAssertEqual(result.txid, try string("txid", in: signing))
        XCTAssertTrue(result.verdict.ok)
        XCTAssertFalse(result.signedPsbt.isEmpty)
        XCTAssertNotEqual(result.signedPsbt, unsigned, "signing must change the PSBT")
    }

    func testSigningRefusesWhenTheIntentDoesNotMatch() throws {
        let keys = try ourKeys()
        let unsigned = try string("unsignedPsbt", in: signingFixture())
        var tampered = try fixtureSendBtcIntent()
        tampered.recipients[0].amountSat = 40_001

        XCTAssertThrowsError(try verifyAndSignPsbt(keys: keys, psbt: unsigned, params: try fixtureParams(keys: keys, intent: tampered))) { error in
            guard case SdkError.VerificationFailed(let check, _) = error else {
                return XCTFail("expected VerificationFailed, got \(error)")
            }
            XCTAssertEqual(check, "recipients-match")
        }
    }

    func testErrorsCrossTheBoundaryAsTypedErrors() {
        XCTAssertThrowsError(try ClientKeys.fromMnemonic(mnemonic: "abandon abandon abandon", network: .regtest)) { error in
            guard case SdkError.InvalidMnemonic = error else {
                return XCTFail("expected InvalidMnemonic, got \(error)")
            }
        }
        XCTAssertThrowsError(try deriveTaprootAddress(accountXpub: "not-an-xpub", keychain: 0, index: 0, network: .regtest)) { error in
            guard case SdkError.InvalidInput = error else {
                return XCTFail("expected InvalidInput, got \(error)")
            }
        }
    }

    func testInvoiceDecodersCrossTheBoundaryWithOptionalsListsAndEnums() throws {
        let bolt11 = try decodeBolt11(invoice: Self.bolt11Coffee)
        XCTAssertEqual(bolt11.network, .mainnet)
        XCTAssertEqual(bolt11.amountMsat, 250_000_000)
        XCTAssertEqual(bolt11.description, "1 cup coffee")
        XCTAssertNil(bolt11.descriptionHash)
        XCTAssertEqual(bolt11.expirySeconds, 60)
        XCTAssertEqual(bolt11.paymentHash.count, 64)
        XCTAssertEqual(bolt11.payeeNodeId.count, 66)

        let wr = try object("witnessReceive", in: fixture())
        let rgb = try decodeRgbInvoice(invoice: try string("invoice", in: wr))
        XCTAssertEqual(rgb.recipientId, try string("recipientId", in: wr))
        XCTAssertEqual(rgb.beneficiaryKind, .witness)
        XCTAssertNil(rgb.assetId)
        XCTAssertNil(rgb.amount)
        XCTAssertEqual(rgb.chain, "bcrt")
        XCTAssertEqual(rgb.transportEndpoints, ["rpc://localhost:3000/json-rpc"])
        XCTAssertEqual(rgb.expiryTimestamp, (wr["expirationTimestamp"] as? NSNumber).map { UInt64(truncating: $0) })

        XCTAssertThrowsError(try decodeBolt11(invoice: "lnbc1pvjluez")) { error in
            guard case SdkError.InvoiceDecode = error else { return XCTFail("expected InvoiceDecode, got \(error)") }
        }
        XCTAssertThrowsError(try decodeRgbInvoice(invoice: "not an invoice")) { error in
            guard case SdkError.InvoiceDecode = error else { return XCTFail("expected InvoiceDecode, got \(error)") }
        }
    }

    func testIdempotencyKeysAreV4Uuids() throws {
        let key = try generateIdempotencyKey()
        XCTAssertNotNil(
            key.range(of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#, options: .regularExpression),
            key)
        XCTAssertNotEqual(key, try generateIdempotencyKey(), "keys must be unique per call")
    }

    // MARK: foreign transport

    /// A Swift-side transport: records the request Rust built and answers with a canned response.
    private final class StubTransport: HttpTransport {
        let status: UInt16
        let body: String
        private(set) var requests: [HttpRequest] = []

        init(status: UInt16, body: String) {
            self.status = status
            self.body = body
        }

        func send(request: HttpRequest) throws -> HttpResponse {
            requests.append(request)
            return HttpResponse(status: status, body: body)
        }
    }

    /// A transport that throws instead of answering.
    private final class ThrowingTransport: HttpTransport {
        let error: Error
        init(error: Error) { self.error = error }
        func send(request: HttpRequest) throws -> HttpResponse { throw error }
    }

    private struct HostError: Error, CustomStringConvertible {
        let description: String
    }

    private func client(_ transport: HttpTransport) -> GatewayClient {
        GatewayClient(baseUrl: Self.gateway, token: Self.token, timeoutMs: nil, transport: transport)
    }

    func testGatewayClientDrivesASwiftHttpTransport() throws {
        let transport = StubTransport(status: 200, body: #"{"userId":"user-1","createdAt":1700000000}"#)
        let me = try client(transport).me()
        XCTAssertEqual(me.userId, "user-1")
        XCTAssertEqual(me.createdAt, 1_700_000_000)

        XCTAssertEqual(transport.requests.count, 1)
        let request = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(request.method, .get)
        XCTAssertEqual(request.url, "https://gateway.example/v1/me")
        XCTAssertEqual(request.headers["authorization"], "Bearer secret-token")
        XCTAssertNil(request.body)
        XCTAssertGreaterThan(request.timeoutMs, 0)
    }

    func testGatewayErrorsSurfaceStatusAndCodeFromTheTransport() {
        let transport = StubTransport(status: 503, body: #"{"error":{"code":"MAINTENANCE","message":"back soon"}}"#)
        XCTAssertThrowsError(try client(transport).me()) { error in
            guard case SdkError.Gateway(let status, let code, _) = error else {
                return XCTFail("expected Gateway, got \(error)")
            }
            XCTAssertEqual(status, 503)
            XCTAssertEqual(code, "MAINTENANCE")
            XCTAssertFalse(String(describing: error).contains("secret-token"), "bearer token leaked into the error")
            XCTAssertFalse(error.localizedDescription.contains("secret-token"), "bearer token leaked into the error")
        }
    }

    func testTransportErrorsCrossBackIntoRustAsTypedTransportErrors() {
        // The declared error type passes through unchanged.
        XCTAssertThrowsError(try client(ThrowingTransport(error: SdkError.Transport(reason: "dns failed"))).me()) { error in
            guard case SdkError.Transport(let reason) = error else {
                return XCTFail("expected Transport, got \(error)")
            }
            XCTAssertEqual(reason, "dns failed")
        }
        // A host error that is not an SdkError must still surface as a typed
        // Transport error, never as an internal (panic) error.
        XCTAssertThrowsError(try client(ThrowingTransport(error: HostError(description: "pool closed"))).me()) { error in
            guard case SdkError.Transport(let reason) = error else {
                return XCTFail("expected Transport, got \(error)")
            }
            XCTAssertTrue(reason.contains("unexpected"), reason)
            XCTAssertTrue(reason.contains("pool closed"), reason)
            XCTAssertFalse(String(describing: error).contains(Self.token), "bearer token leaked into the error")
        }
    }

    func testPrepareSendBtcBindsTheIntentAndSurfacesNestedRecords() throws {
        let transport = StubTransport(status: 200, body: Self.preparedSendBtc)
        let op = try client(transport).prepareSendBtc(
            params: PrepareSendBtcParams(address: Self.address, amountSat: 40_000, feeRateSatPerVb: nil),
            idempotencyKey: nil)
        XCTAssertEqual(op.opId, "op-1")
        XCTAssertEqual(op.psbt, "cHNidP8=")
        XCTAssertEqual(op.expiresAt, 1_700_000_000)
        XCTAssertEqual(op.intent.kind, .sendBtc)
        XCTAssertEqual(op.intent.feeRateSatPerVb, 2)
        XCTAssertNil(op.intent.asset)
        XCTAssertNil(op.intent.utxos)
        XCTAssertEqual(op.intent.recipients, [IntentRecipient(address: Self.address, scriptHex: "0014deadbeef", amountSat: 40_000)])
        let request = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(request.method, .post)
        XCTAssertEqual(request.url, "\(Self.gateway)/v1/onchain/send-btc/prepare")
        XCTAssertEqual(request.headers["content-type"], "application/json")
        XCTAssertNotNil(request.headers["idempotency-key"])
        let body = try JSONSerialization.jsonObject(with: Data(try XCTUnwrap(request.body).utf8)) as? [String: Any]
        XCTAssertEqual(body?["address"] as? String, Self.address)

        // The same gateway response does not match a request for another address.
        XCTAssertThrowsError(try client(StubTransport(status: 200, body: Self.preparedSendBtc)).prepareSendBtc(
            params: PrepareSendBtcParams(address: Self.attacker, amountSat: 40_000, feeRateSatPerVb: nil),
            idempotencyKey: nil)) { error in
            guard case SdkError.IntentMismatch(let reason) = error else {
                return XCTFail("expected IntentMismatch, got \(error)")
            }
            XCTAssertTrue(reason.contains("recipient address"), reason)
        }
    }

    func testLnBalanceMapsCrossTheBoundary() throws {
        let transport = StubTransport(status: 200, body: #"{"btcMsat":12345,"assets":{"rgb:a":7,"rgb:b":0}}"#)
        let balance = try client(transport).getLnBalance()
        XCTAssertEqual(balance.btcMsat, 12_345)
        XCTAssertEqual(balance.assets, ["rgb:a": 7, "rgb:b": 0])
    }

    // MARK: URLSessionHttpTransport

    /// In-process stand-in for the network: records what URLSession was asked
    /// to send and answers with the configured status and body, so the shipped
    /// transport is exercised without a socket.
    private final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        private var _status = 200
        private var _body = Data()
        private var _hang = false
        private var _request: URLRequest?
        private var _requestBody: Data?

        func configure(status: Int, body: Data, hang: Bool = false) {
            lock.lock(); defer { lock.unlock() }
            _status = status; _body = body; _hang = hang; _request = nil; _requestBody = nil
        }
        var status: Int { lock.lock(); defer { lock.unlock() }; return _status }
        var body: Data { lock.lock(); defer { lock.unlock() }; return _body }
        var hang: Bool { lock.lock(); defer { lock.unlock() }; return _hang }
        var request: URLRequest? { lock.lock(); defer { lock.unlock() }; return _request }
        var requestBody: Data? { lock.lock(); defer { lock.unlock() }; return _requestBody }
        func record(_ request: URLRequest, body: Data?) {
            lock.lock(); defer { lock.unlock() }
            _request = request; _requestBody = body
        }
    }

    private static let recorder = Recorder()

    private final class StubURLProtocol: URLProtocol {
        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

        override func startLoading() {
            let recorder = SmokeTests.recorder
            recorder.record(request, body: request.httpBody ?? request.httpBodyStream.map(Self.drain))
            if recorder.hang { return }
            guard let url = request.url,
                  let response = HTTPURLResponse(url: url, statusCode: recorder.status, httpVersion: "HTTP/1.1", headerFields: [:])
            else {
                client?.urlProtocol(self, didFailWithError: HostError(description: "stub could not build a response"))
                return
            }
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: recorder.body)
            client?.urlProtocolDidFinishLoading(self)
        }

        override func stopLoading() {}

        private static func drain(_ stream: InputStream) -> Data {
            stream.open()
            defer { stream.close() }
            var data = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let read = stream.read(&buffer, maxLength: buffer.count)
                if read <= 0 { break }
                data.append(buffer, count: read)
            }
            return data
        }
    }

    private func stubbedSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    func testUrlSessionTransportRejectsAnInvalidUrlWithoutTouchingTheNetwork() {
        let transport = URLSessionHttpTransport()
        let request = HttpRequest(method: .get, url: "not a url", headers: [:], body: nil, timeoutMs: 1_000)
        XCTAssertThrowsError(try transport.send(request: request)) { error in
            guard case SdkError.Transport = error else {
                return XCTFail("expected Transport, got \(error)")
            }
        }
    }

    func testUrlSessionTransportForwardsTheRequestVerbatimAndReturnsAnyStatus() throws {
        let recorder = Self.recorder
        let transport = URLSessionHttpTransport(session: stubbedSession())

        // A 5xx is returned as a response (status intact), which Rust maps to
        // a Gateway error; it is not a Transport error.
        recorder.configure(status: 503, body: Data(#"{"error":{"code":"MAINTENANCE","message":"back soon"}}"#.utf8))
        let gateway = GatewayClient(baseUrl: Self.gateway, token: Self.token, timeoutMs: 1_500, transport: transport)
        XCTAssertThrowsError(try gateway.me()) { error in
            guard case SdkError.Gateway(let status, let code, _) = error else {
                return XCTFail("expected Gateway, got \(error)")
            }
            XCTAssertEqual(status, 503)
            XCTAssertEqual(code, "MAINTENANCE")
        }
        let get = try XCTUnwrap(recorder.request)
        XCTAssertEqual(get.httpMethod, "GET")
        XCTAssertEqual(get.url?.absoluteString, "\(Self.gateway)/v1/me")
        XCTAssertEqual(get.value(forHTTPHeaderField: "authorization"), "Bearer \(Self.token)")
        XCTAssertEqual(get.timeoutInterval, 1.5, accuracy: 0.001)

        // A POST carries the JSON body and headers Rust built, byte for byte.
        recorder.configure(status: 200, body: Data(Self.preparedSendBtc.utf8))
        let op = try gateway.prepareSendBtc(
            params: PrepareSendBtcParams(address: Self.address, amountSat: 40_000, feeRateSatPerVb: nil),
            idempotencyKey: "11111111-2222-4333-8444-555555555555")
        XCTAssertEqual(op.opId, "op-1")
        let post = try XCTUnwrap(recorder.request)
        XCTAssertEqual(post.httpMethod, "POST")
        XCTAssertEqual(post.value(forHTTPHeaderField: "content-type"), "application/json")
        XCTAssertEqual(post.value(forHTTPHeaderField: "idempotency-key"), "11111111-2222-4333-8444-555555555555")
        let sent = try JSONSerialization.jsonObject(with: try XCTUnwrap(recorder.requestBody)) as? [String: Any]
        XCTAssertEqual(sent?["address"] as? String, Self.address)
        XCTAssertEqual((sent?["amountSat"] as? NSNumber).map { UInt64(truncating: $0) }, 40_000)

        // A non-UTF-8 error page keeps its status instead of becoming a
        // Transport error.
        recorder.configure(status: 500, body: Data([0xff, 0xfe, 0x00, 0xc3]))
        XCTAssertThrowsError(try gateway.me()) { error in
            guard case SdkError.Gateway(let status, let code, _) = error else {
                return XCTFail("expected Gateway, got \(error)")
            }
            XCTAssertEqual(status, 500)
            XCTAssertEqual(code, "UNKNOWN")
        }
    }

    func testUrlSessionTransportBoundsTheTotalWaitByTimeoutMs() {
        let recorder = Self.recorder
        defer { recorder.configure(status: 200, body: Data()) }
        recorder.configure(status: 200, body: Data(), hang: true)
        let transport = URLSessionHttpTransport(session: stubbedSession())
        let request = HttpRequest(method: .get, url: "\(Self.gateway)/v1/me", headers: [:], body: nil, timeoutMs: 300)
        let started = Date()
        XCTAssertThrowsError(try transport.send(request: request)) { error in
            guard case SdkError.Transport(let reason) = error else {
                return XCTFail("expected Transport, got \(error)")
            }
            XCTAssertTrue(reason.contains("timed out"), reason)
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5, "the caller must not be held past the budget")
    }
}
