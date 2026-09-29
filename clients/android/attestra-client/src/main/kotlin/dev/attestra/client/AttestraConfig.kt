package dev.attestra.client

/**
 * Client configuration.
 *
 * @property baseUrl The worker origin, e.g. `https://attestra.example.workers.dev`. Routes are
 *   resolved from its root, so it must not carry a path.
 * @property refreshMarginMillis Sessions are refreshed this long before they expire.
 * @property packageName Sent with attestations only when the worker serves several packages
 *   (`ANDROID_PACKAGE_NAMES` lists more than one).
 */
data class AttestraConfig(
    val baseUrl: String,
    val refreshMarginMillis: Long = 60_000,
    val packageName: String? = null,
)

/** A short-lived Attestra session. */
data class Session(val token: String, val expiresAtMillis: Long)

/** The worker answered with `{"error": code}` and a non-2xx [status]. */
class AttestraException(val status: Int, val code: String) :
    Exception("Attestra request failed: $status $code")

/** The worker answered with something other than the documented JSON. */
class InvalidResponseException(message: String) : Exception(message)
