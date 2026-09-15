package com.utexo.minimalsdk

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Smoke test through the generated uniffi bindings.
 *
 * Deep assertions (parity for every network and index, the adversarial
 * verify suite, secrets hygiene) live in the Rust crate's `tests/parity.rs`.
 * This test proves the binding surface, the native library load through JNA
 * and the `with_foreign` `HttpTransport` trait work end to end, against the
 * same rgb-lib-authored fixture the Rust suite reads, by relative path.
 */
class SmokeTest {
    private companion object {
        /** BOLT-11 spec vector: 2 500 µBTC, "1 cup coffee", 60 s expiry. */
        const val BOLT11_COFFEE =
            "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh"
        const val ADDRESS = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        const val ATTACKER = "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        const val GATEWAY = "https://gateway.example"
        const val TOKEN = "secret-token"
        val PREPARED_SEND_BTC = """{"opId":"op-1","psbt":"cHNidP8=","expiresAt":1700000000,""" +
            """"intent":{"kind":"send_btc","feeRateSatPerVb":2,""" +
            """"recipients":[{"address":"$ADDRESS","scriptHex":"0014deadbeef","amountSat":40000}],""" +
            """"asset":null,"utxos":null}}"""
    }

    private val fixture: JSONObject by lazy {
        val path = System.getProperty("utexo.minimalsdk.fixture")
            ?: "../packages/client-sdk/test/fixtures/rgblib-parity.json"
        val file = File(path)
        assertTrue(file.isFile, "parity fixture missing at ${file.absolutePath}")
        JSONObject(file.readText())
    }

    private val regtestFixture: JSONObject get() = fixture.getJSONObject("networks").getJSONObject("Regtest")

    private fun ourKeys(): ClientKeys =
        ClientKeys.fromMnemonic(fixture.getString("mnemonic"), BitcoinNetwork.REGTEST)

    private fun foreignKeys(): ClientKeys =
        ClientKeys.fromMnemonic(fixture.getString("otherMnemonic"), BitcoinNetwork.REGTEST)

    /** The intent the fixture PSBT was prepared for: 40 000 sat to the foreign wallet's vanilla address 0. */
    private fun fixtureSendBtcIntent(): OnchainIntent {
        val foreign = deriveTaprootAddress(foreignKeys().xpubs().vanilla, 0u, 0u, BitcoinNetwork.REGTEST)
        return OnchainIntent(
            kind = IntentKind.SEND_BTC,
            feeRateSatPerVb = 2UL,
            recipients = listOf(
                IntentRecipient(address = foreign.address, scriptHex = foreign.scriptHex, amountSat = 40_000UL),
            ),
            asset = null,
            utxos = null,
        )
    }

    private fun fixtureParams(keys: ClientKeys, intent: OnchainIntent = fixtureSendBtcIntent()) =
        VerifyParams(intent = intent, xpubs = keys.xpubs(), maxFeeSat = 2_000UL)

    @Test
    fun nativeLibraryLoadsAndReportsVersion() {
        val version = sdkVersion()
        assertTrue(version.isNotEmpty())
        assertTrue(Regex("""\d+\.\d+\.\d+""").matches(version), "semver expected, got $version")
    }

    @Test
    fun restoreFromFixtureMnemonicMatchesRgbLibXpubsAndFingerprint() {
        val keys = ourKeys()
        val expected = regtestFixture
        assertEquals(BitcoinNetwork.REGTEST, keys.network())
        assertEquals(expected.getString("masterFingerprint"), keys.fingerprint())

        val xpubs = keys.xpubs()
        assertEquals(BitcoinNetwork.REGTEST, xpubs.network)
        assertEquals(expected.getString("masterFingerprint"), xpubs.fingerprint)
        assertEquals(expected.getString("accountXpubVanilla"), xpubs.vanilla)
        assertEquals(expected.getString("accountXpubColored"), xpubs.colored)
        // Public material only crosses the boundary.
        assertFalse(xpubs.vanilla.startsWith("tprv") || xpubs.colored.startsWith("tprv"))
    }

    @Test
    fun deriveIndexZeroMatchesRgbLibAddresses() {
        val xpubs = ourKeys().xpubs()
        val regtest = fixture.getJSONObject("regtest")

        val vanilla = deriveTaprootAddress(xpubs.vanilla, 0u, 0u, BitcoinNetwork.REGTEST)
        assertEquals(regtest.getJSONArray("vanillaAddresses").getString(0), vanilla.address)
        assertEquals(0u, vanilla.keychain)
        assertEquals(0u, vanilla.index)
        assertTrue(vanilla.scriptHex.startsWith("5120") && vanilla.scriptHex.length == 68)

        val colored = deriveTaprootAddress(xpubs.colored, 0u, 0u, BitcoinNetwork.REGTEST)
        assertEquals(regtest.getJSONArray("coloredAddresses").getString(0), colored.address)
    }

    @Test
    fun verifyAndSignFixturePsbtReachesRgbLibTxid() {
        val keys = ourKeys()
        val signing = fixture.getJSONObject("signing")
        val unsigned = signing.getString("unsignedPsbt")
        val params = fixtureParams(keys)

        val verdict = verifyPsbt(unsigned, params)
        assertTrue(verdict.ok, "verdict failed: ${verdict.checks.filter { !it.ok }}")
        assertEquals(5, verdict.checks.size)

        val result = verifyAndSignPsbt(keys, unsigned, params)
        assertEquals(signing.getString("txid"), result.txid)
        assertTrue(result.verdict.ok)
        assertTrue(result.signedPsbt.isNotEmpty())
        assertTrue(result.signedPsbt != unsigned, "signing must change the PSBT")
    }

    @Test
    fun signingRefusesWhenTheIntentDoesNotMatch() {
        val keys = ourKeys()
        val unsigned = fixture.getJSONObject("signing").getString("unsignedPsbt")
        val tampered = fixtureSendBtcIntent().let { intent ->
            intent.copy(recipients = listOf(intent.recipients[0].copy(amountSat = 40_001UL)))
        }
        val error = assertFailsWith<SdkException.VerificationFailed> {
            verifyAndSignPsbt(keys, unsigned, fixtureParams(keys, tampered))
        }
        assertEquals("recipients-match", error.check)
    }

    @Test
    fun errorsCrossTheBoundaryAsTypedExceptions() {
        assertFailsWith<SdkException.InvalidMnemonic> {
            ClientKeys.fromMnemonic("abandon abandon abandon", BitcoinNetwork.REGTEST)
        }
        assertFailsWith<SdkException.InvalidInput> {
            deriveTaprootAddress("not-an-xpub", 0u, 0u, BitcoinNetwork.REGTEST)
        }
    }

    /** A Kotlin-side transport: records the request Rust built and answers with a canned response. */
    private class StubTransport(private val status: UShort, private val body: String) : HttpTransport {
        val requests = mutableListOf<HttpRequest>()
        override fun send(request: HttpRequest): HttpResponse {
            requests += request
            return HttpResponse(status, body)
        }
    }

    @Test
    fun gatewayClientDrivesAKotlinHttpTransport() {
        val transport = StubTransport(200u, """{"userId":"user-1","createdAt":1700000000}""")
        val client = GatewayClient("https://gateway.example", "secret-token", null, transport)

        val me = client.me()
        assertEquals("user-1", me.userId)
        assertEquals(1_700_000_000UL, me.createdAt)

        val request = transport.requests.single()
        assertEquals(HttpMethod.GET, request.method)
        assertEquals("https://gateway.example/v1/me", request.url)
        assertEquals("Bearer secret-token", request.headers["authorization"])
        assertEquals(null, request.body)
        assertTrue(request.timeoutMs > 0UL)
    }

    @Test
    fun gatewayErrorsSurfaceStatusAndCodeFromTheTransport() {
        val transport = StubTransport(503u, """{"error":{"code":"MAINTENANCE","message":"back soon"}}""")
        val client = GatewayClient("https://gateway.example", "secret-token", null, transport)
        val error = assertFailsWith<SdkException.Gateway> { client.me() }
        assertEquals(503u.toUShort(), error.status)
        assertEquals("MAINTENANCE", error.code)
        assertFalse(error.toString().contains("secret-token"), "bearer token leaked into the error")
    }

    /** A transport that throws instead of answering. */
    private class ThrowingTransport(private val error: Throwable) : HttpTransport {
        override fun send(request: HttpRequest): HttpResponse = throw error
    }

    @Test
    fun transportErrorsCrossBackIntoRustAsTypedTransportExceptions() {
        // The declared error type passes through unchanged.
        val declared = GatewayClient(GATEWAY, TOKEN, null, ThrowingTransport(SdkException.Transport("dns failed")))
        assertEquals("dns failed", assertFailsWith<SdkException.Transport> { declared.me() }.reason)

        // A host exception that is not an SdkException must still surface as a
        // typed Transport error, never as an internal (panic) exception.
        val foreign = GatewayClient(GATEWAY, TOKEN, null, ThrowingTransport(IllegalStateException("pool closed")))
        val mapped = assertFailsWith<SdkException.Transport> { foreign.me() }
        assertTrue(mapped.reason.contains("unexpected"), mapped.reason)
        assertTrue(mapped.reason.contains("pool closed"), mapped.reason)
        assertFalse(mapped.toString().contains(TOKEN), "bearer token leaked into the error")
    }

    @Test
    fun generatedKeysRestoreToTheSameXpubs() {
        val generated = generateKeys(BitcoinNetwork.REGTEST)
        assertEquals(12, generated.mnemonic.trim().split(" ").size)
        val restored = ClientKeys.fromMnemonic(generated.mnemonic, BitcoinNetwork.REGTEST)
        assertEquals(generated.keys.xpubs(), restored.xpubs())
        assertEquals(generated.keys.fingerprint(), restored.fingerprint())
        assertEquals(BitcoinNetwork.REGTEST, generated.keys.network())
        assertTrue(generated.keys.xpubs().vanilla.startsWith("tpub"))
        // A fresh generation is a different wallet.
        assertTrue(generateKeys(BitcoinNetwork.REGTEST).keys.xpubs() != generated.keys.xpubs())
    }

    @Test
    fun invoiceDecodersCrossTheBoundaryWithOptionalsListsAndEnums() {
        val bolt11 = decodeBolt11(BOLT11_COFFEE)
        assertEquals(BitcoinNetwork.MAINNET, bolt11.network)
        assertEquals(250_000_000UL, bolt11.amountMsat)
        assertEquals("1 cup coffee", bolt11.description)
        assertEquals(null, bolt11.descriptionHash)
        assertEquals(60UL, bolt11.expirySeconds)
        assertEquals(64, bolt11.paymentHash.length)
        assertEquals(66, bolt11.payeeNodeId.length)

        val wr = fixture.getJSONObject("witnessReceive")
        val rgb = decodeRgbInvoice(wr.getString("invoice"))
        assertEquals(wr.getString("recipientId"), rgb.recipientId)
        assertEquals(BeneficiaryKind.WITNESS, rgb.beneficiaryKind)
        assertEquals(null, rgb.assetId)
        assertEquals(null, rgb.amount)
        assertEquals("bcrt", rgb.chain)
        assertEquals(listOf("rpc://localhost:3000/json-rpc"), rgb.transportEndpoints)
        assertEquals(wr.getLong("expirationTimestamp").toULong(), rgb.expiryTimestamp)

        assertFailsWith<SdkException.InvoiceDecode> { decodeBolt11("lnbc1pvjluez") }
        assertFailsWith<SdkException.InvoiceDecode> { decodeRgbInvoice("not an invoice") }
    }

    @Test
    fun idempotencyKeysAreV4Uuids() {
        val key = generateIdempotencyKey()
        assertTrue(Regex("""[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}""").matches(key), key)
        assertTrue(key != generateIdempotencyKey(), "keys must be unique per call")
    }

    @Test
    fun prepareSendBtcBindsTheIntentAndSurfacesNestedRecords() {
        val transport = StubTransport(200u, PREPARED_SEND_BTC)
        val client = GatewayClient(GATEWAY, TOKEN, null, transport)
        val op = client.prepareSendBtc(PrepareSendBtcParams(ADDRESS, 40_000UL, null), null)
        assertEquals("op-1", op.opId)
        assertEquals("cHNidP8=", op.psbt)
        assertEquals(1_700_000_000UL, op.expiresAt)
        assertEquals(IntentKind.SEND_BTC, op.intent.kind)
        assertEquals(2UL, op.intent.feeRateSatPerVb)
        assertEquals(null, op.intent.asset)
        assertEquals(null, op.intent.utxos)
        assertEquals(IntentRecipient(ADDRESS, "0014deadbeef", 40_000UL), op.intent.recipients.single())
        val request = transport.requests.single()
        assertEquals(HttpMethod.POST, request.method)
        assertEquals("$GATEWAY/v1/onchain/send-btc/prepare", request.url)
        assertEquals("application/json", request.headers["content-type"])
        assertTrue(request.headers.containsKey("idempotency-key"))
        assertTrue(JSONObject(request.body!!).getString("address") == ADDRESS)

        // The same gateway response does not match a request for another address.
        val tampered = GatewayClient(GATEWAY, TOKEN, null, StubTransport(200u, PREPARED_SEND_BTC))
        val error = assertFailsWith<SdkException.IntentMismatch> {
            tampered.prepareSendBtc(PrepareSendBtcParams(ATTACKER, 40_000UL, null), null)
        }
        assertTrue(error.reason.contains("recipient address"), error.reason)
    }

    @Test
    fun lnBalanceMapsCrossTheBoundary() {
        val transport = StubTransport(200u, """{"btcMsat":12345,"assets":{"rgb:a":7,"rgb:b":0}}""")
        val balance = GatewayClient(GATEWAY, TOKEN, null, transport).getLnBalance()
        assertEquals(12_345UL, balance.btcMsat)
        assertEquals(mapOf("rgb:a" to 7UL, "rgb:b" to 0UL), balance.assets)
    }

    @Test
    fun consumerRulesKeepOnlyJnaEntryPoints() {
        val rules = File(System.getProperty("utexo.minimalsdk.consumerRules") ?: "consumer-rules.pro")
        assertTrue(rules.isFile, "consumer-rules.pro missing at ${rules.absolutePath}")
        val lines = rules.readLines().map { it.trim() }
        val keeps = lines.filter { it.startsWith("-keep ") }
        assertTrue(keeps.isNotEmpty())
        // JNA reads @Structure.FieldOrder reflectively; R8 strips runtime annotations unless kept.
        assertTrue(
            lines.any { it.startsWith("-keepattributes") && it.contains("RuntimeVisibleAnnotations") },
            "consumer-rules.pro must keep RuntimeVisibleAnnotations for JNA @Structure.FieldOrder",
        )
        assertTrue(keeps.none { it.contains("com.utexo.minimalsdk") }, "blanket keep of the SDK package: $keeps")
        assertNotNull(keeps.find { it.contains("com.sun.jna.Library") })
        assertNotNull(keeps.find { it.contains("com.sun.jna.Callback") })
        assertNotNull(keeps.find { it.contains("com.sun.jna.Structure") })
    }
}
