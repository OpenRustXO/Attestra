package dev.attestra.client

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONException
import org.json.JSONObject

/**
 * Attests the app with Play Integrity, keeps a session fresh, and calls providers through the
 * Attestra proxy. Thread-safe; share one instance.
 *
 * ```kotlin
 * val client = AttestraClient(
 *     AttestraConfig(baseUrl = "https://attestra.example.workers.dev"),
 *     PlayIntegrityTokenSource(context, cloudProjectNumber = 123456789L),
 *     SharedPreferencesInstallIdStore(context),
 * )
 * client.warmUp()
 * val response = client.send(ProxyRequest("openai", "/v1/chat/completions", "POST", body = json))
 * ```
 */
class AttestraClient(
    private val config: AttestraConfig,
    private val integrity: IntegrityTokenSource,
    private val installIds: InstallIdStore,
    private val transport: HttpTransport = UrlConnectionTransport(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val mutex = Mutex()

    @Volatile
    private var session: Session? = null

    /** Prepares Play Integrity ahead of the first attestation. */
    suspend fun warmUp() = integrity.warmUp()

    /**
     * Returns a valid session, attesting when there is none or it is about to expire.
     * Concurrent callers share one attestation. Pass [rejectedToken] to force a new session
     * unless another caller already replaced that token.
     */
    suspend fun currentSession(rejectedToken: String? = null): Session {
        session?.takeIf { isUsable(it, rejectedToken) }?.let { return it }
        return mutex.withLock {
            session?.takeIf { isUsable(it, rejectedToken) } ?: attest().also { session = it }
        }
    }

    /**
     * Sends a request through the proxy. If Attestra rejects the session with 401, a new
     * session is obtained and the request retried exactly once. Upstream responses (including
     * upstream 401s) are returned unchanged.
     */
    suspend fun send(request: ProxyRequest): HttpResponse {
        val first = currentSession()
        val response = sendWith(request, first)
        if (response.status != 401 || !isAttestraAuthError(response.body)) return response
        return sendWith(request, currentSession(rejectedToken = first.token))
    }

    /** Forgets the cached session. */
    fun reset() {
        session = null
    }

    private fun isUsable(session: Session, rejectedToken: String?): Boolean =
        session.token != rejectedToken && session.expiresAtMillis - clock() > config.refreshMarginMillis

    private suspend fun sendWith(request: ProxyRequest, session: Session): HttpResponse {
        val headers = request.headers + ("Authorization" to "Bearer ${session.token}")
        return transport.execute(
            HttpRequest(request.method.uppercase(), RequestBuilder.url(config.baseUrl, request), headers, request.body),
        )
    }

    private suspend fun attest(): Session {
        val challengeResponse = postJson("/challenge", null)
        val challengeText = challengeResponse.optString("challenge")
        val challenge = Base64Url.decode(challengeText)
        if (challenge == null || challenge.size != 32) throw InvalidResponseException("malformed challenge")

        val installId = installIds.installId()
        val token = integrity.requestToken(requestHash(challenge, installId))
        val body = JSONObject()
            .put("integrity_token", token)
            .put("challenge", challengeText)
            .put("install_id", installId)
        config.packageName?.let { body.put("package_name", it) }

        val response = postJson("/attest/android", body)
        val sessionToken = response.optString("token")
        val expiresAt = response.optLong("expires_at", 0)
        if (sessionToken.isEmpty() || expiresAt == 0L) throw InvalidResponseException("malformed session")
        return Session(sessionToken, expiresAt * 1000)
    }

    private suspend fun postJson(path: String, body: JSONObject?): JSONObject {
        val response = transport.execute(
            HttpRequest(
                method = "POST",
                url = config.baseUrl.trimEnd('/') + path,
                headers = mapOf("Content-Type" to "application/json"),
                body = (body ?: JSONObject()).toString().toByteArray(Charsets.UTF_8),
            ),
        )
        if (response.status !in 200..299) {
            throw AttestraException(response.status, errorCode(response.body) ?: "unknown")
        }
        return try {
            JSONObject(response.body.toString(Charsets.UTF_8))
        } catch (e: JSONException) {
            throw InvalidResponseException("response is not JSON")
        }
    }

    internal companion object {
        fun errorCode(body: ByteArray): String? = try {
            JSONObject(body.toString(Charsets.UTF_8)).optString("error").takeIf { it.isNotEmpty() }
        } catch (e: JSONException) {
            null
        }

        /** A 401 produced by Attestra itself, as opposed to one relayed from the provider. */
        fun isAttestraAuthError(body: ByteArray): Boolean =
            errorCode(body) in setOf("session_invalid", "attestation_invalid")
    }
}
