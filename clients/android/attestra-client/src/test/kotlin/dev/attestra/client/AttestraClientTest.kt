package dev.attestra.client

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections

private const val INSTALL_ID = "6f46aaeb-3989-45db-8c24-6cc88a76e789"
private const val BASE = "https://attestra.example.dev"

/** Records requested hashes and hands out numbered tokens. */
private class FakeIntegrity : IntegrityTokenSource {
    val hashes: MutableList<String> = Collections.synchronizedList(mutableListOf())
    var warmUps = 0

    override suspend fun warmUp() {
        warmUps++
    }

    override suspend fun requestToken(requestHash: String): String {
        hashes += requestHash
        return "integrity-${hashes.size}"
    }
}

/** A fake worker that issues challenges and sessions and replays scripted proxy responses. */
private class FakeWorker(private val clock: () -> Long) : HttpTransport {
    val requests: MutableList<HttpRequest> = Collections.synchronizedList(mutableListOf())
    val challenges = mutableListOf<ByteArray>()
    var attestResponse: Pair<Int, String>? = null
    val proxyResponses = ArrayDeque<Pair<Int, String>>()
    private var sessions = 0

    fun paths() = requests.map { it.url.removePrefix(BASE).substringBefore('?') }

    override suspend fun execute(request: HttpRequest): HttpResponse {
        requests += request
        val path = request.url.removePrefix(BASE).substringBefore('?')
        val (status, body) = when {
            path == "/challenge" -> {
                val challenge = ByteArray(32) { (challenges.size * 32 + it).toByte() }
                challenges += challenge
                200 to """{"challenge":"${Base64Url.encode(challenge)}","expires_at":0}"""
            }
            path == "/attest/android" -> attestResponse?.also { attestResponse = null }
                ?: (200 to """{"token":"session-${++sessions}","expires_at":${clock() / 1000 + 900}}""")
            else -> proxyResponses.removeFirstOrNull() ?: (200 to "upstream ok")
        }
        return HttpResponse(status, emptyMap(), body.toByteArray())
    }
}

class AttestraClientTest {
    private var now = 1_750_000_000_000L
    private val integrity = FakeIntegrity()
    private val worker = FakeWorker { now }
    private val client = AttestraClient(AttestraConfig(BASE), integrity, { INSTALL_ID }, worker) { now }

    @Test
    fun attestsOnceAndCachesTheSession() = runTest {
        val first = client.currentSession()
        val second = client.currentSession()
        assertEquals(first, second)
        assertEquals(listOf("/challenge", "/attest/android"), worker.paths())

        // requestHash = base64url(SHA256(challenge || install_id))
        val expectedHash = Base64Url.encode(sha256(worker.challenges[0], INSTALL_ID.toByteArray()))
        assertEquals(listOf(expectedHash), integrity.hashes)

        val body = JSONObject(worker.requests[1].body!!.toString(Charsets.UTF_8))
        assertEquals("integrity-1", body.getString("integrity_token"))
        assertEquals(Base64Url.encode(worker.challenges[0]), body.getString("challenge"))
        assertEquals(INSTALL_ID, body.getString("install_id"))
        assertTrue(!body.has("package_name"))
    }

    @Test
    fun sendsPackageNameWhenConfigured() = runTest {
        val client = AttestraClient(AttestraConfig(BASE, packageName = "com.example.app"), integrity, { INSTALL_ID }, worker) { now }
        client.currentSession()
        assertEquals("com.example.app", JSONObject(worker.requests[1].body!!.toString(Charsets.UTF_8)).getString("package_name"))
    }

    @Test
    fun refreshesShortlyBeforeExpiry() = runTest {
        client.currentSession()
        now += (900 - 61) * 1000L
        client.currentSession()
        assertEquals(1, worker.paths().count { it == "/attest/android" })
        now += 2_000
        client.currentSession()
        assertEquals(2, worker.paths().count { it == "/attest/android" })
    }

    @Test
    fun concurrentCallersShareOneAttestation() = runTest {
        val sessions = (1..5).map { async { client.currentSession() } }.awaitAll()
        assertEquals(1, sessions.map { it.token }.toSet().size)
        assertEquals(1, worker.paths().count { it == "/attest/android" })
    }

    @Test
    fun surfacesServerErrors() = runTest {
        worker.attestResponse = 403 to """{"error":"forbidden"}"""
        val error = runCatching { client.currentSession() }.exceptionOrNull() as AttestraException
        assertEquals(403, error.status)
        assertEquals("forbidden", error.code)
    }

    @Test
    fun retriesOnceWhenAttestraRejectsTheSession() = runTest {
        worker.proxyResponses += 401 to """{"error":"session_invalid"}"""
        worker.proxyResponses += 200 to "ok"
        val response = client.send(ProxyRequest("openai", "/v1/models"))
        assertEquals(200, response.status)
        assertEquals(
            listOf("/challenge", "/attest/android", "/p/openai/v1/models", "/challenge", "/attest/android", "/p/openai/v1/models"),
            worker.paths(),
        )
        val auth = worker.requests.filter { it.url.contains("/p/") }.map { it.headers["Authorization"] }
        assertNotEquals(auth[0], auth[1])
    }

    @Test
    fun passesUpstream401Through() = runTest {
        worker.proxyResponses += 401 to """{"error":{"message":"Incorrect API key"}}"""
        val response = client.send(ProxyRequest("openai", "/v1/models"))
        assertEquals(401, response.status)
        assertEquals(1, worker.paths().count { it.startsWith("/p/") })
    }

    @Test
    fun warmUpDelegates() = runTest {
        client.warmUp()
        assertEquals(1, integrity.warmUps)
    }

    @Test
    fun resetForgetsTheSession() = runTest {
        client.currentSession()
        client.reset()
        client.currentSession()
        assertEquals(2, worker.paths().count { it == "/attest/android" })
    }
}

class RequestBuilderTest {
    @Test
    fun encodesLikeTheIosClientAndTheWorker() {
        // Same vector as the Swift `RequestBuilderTests` and the worker's `path_and_query` test.
        val url = RequestBuilder.url(
            "$BASE/",
            ProxyRequest(
                provider = "gemini",
                path = "/v1beta/models/gemini pro:generateContent",
                query = listOf("q" to "a&b=c+d 'e'", "flag" to null),
            ),
        )
        assertEquals(
            "$BASE/p/gemini/v1beta/models/gemini%20pro:generateContent?q=a%26b%3Dc%2Bd%20%27e%27&flag",
            url,
        )
        assertEquals("$BASE/p/x/", RequestBuilder.url(BASE, ProxyRequest("x", "/")))
        assertEquals("$BASE/p/x/caf%C3%A9/", RequestBuilder.url(BASE, ProxyRequest("x", "/café/")))
    }

    @Test
    fun rejectsInvalidInput() {
        for ((provider, path) in listOf("OpenAI" to "/x", "" to "/x", "a/b" to "/x", "x" to "x", "x" to "/a/../b", "x" to "/a//b")) {
            assertThrows(IllegalArgumentException::class.java) { RequestBuilder.url(BASE, ProxyRequest(provider, path)) }
        }
    }
}

class EncodingTest {
    @Test
    fun base64UrlRoundTrips() {
        val bytes = byteArrayOf(0xfb.toByte(), 0xff.toByte(), 0xfe.toByte(), 0x00)
        assertEquals("-__-AA", Base64Url.encode(bytes))
        assertArrayEquals(bytes, Base64Url.decode("-__-AA"))
        for (size in 0..40) {
            val data = ByteArray(size) { (it * 37).toByte() }
            assertArrayEquals(data, Base64Url.decode(Base64Url.encode(data)))
        }
        assertNull(Base64Url.decode("A"))
        assertNull(Base64Url.decode("a+b/"))
    }

    @Test
    fun requestHashMatchesTheWorker() {
        // Same inputs as `request_hash_and_device_id_vectors` in crates/attest-google.
        val hash = requestHash(ByteArray(32) { 7 }, INSTALL_ID)
        assertEquals(Base64Url.encode(sha256(ByteArray(32) { 7 }, INSTALL_ID.toByteArray())), hash)
        assertEquals(43, hash.length)
    }
}
