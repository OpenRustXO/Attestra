package dev.attestra.client

/**
 * A call to `ANY /p/{provider}/{path}`.
 *
 * @property path Unencoded path below the provider, e.g. `/v1/chat/completions`.
 */
class ProxyRequest(
    val provider: String,
    val path: String,
    val method: String = "GET",
    val query: List<Pair<String, String?>> = emptyList(),
    val headers: Map<String, String> = emptyMap(),
    val body: ByteArray? = null,
)

/** Builds proxy URLs with the same conservative encoding as the iOS client. */
internal object RequestBuilder {
    private const val UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    private const val PATH_ALLOWED = "$UNRESERVED!$&'()*+,;=:@"
    private const val QUERY_ALLOWED = "$UNRESERVED!$()*,;:@/?"
    private val PROVIDER = Regex("[a-z0-9_-]+")

    fun url(baseUrl: String, request: ProxyRequest): String {
        require(PROVIDER.matches(request.provider)) { "invalid provider name" }
        require(request.path.startsWith("/")) { "path must start with /" }
        val segments = request.path.substring(1).split("/")
        val encodedPath = if (request.path == "/") {
            "/"
        } else {
            segments.withIndex().joinToString("") { (index, segment) ->
                require(segment != "." && segment != "..") { "invalid path segment" }
                require(segment.isNotEmpty() || index == segments.lastIndex) { "empty path segment" }
                "/" + percentEncode(segment, PATH_ALLOWED)
            }
        }
        val query = request.query.joinToString("&") { (name, value) ->
            val encodedName = percentEncode(name, QUERY_ALLOWED)
            if (value == null) encodedName else "$encodedName=${percentEncode(value, QUERY_ALLOWED)}"
        }
        return baseUrl.trimEnd('/') + "/p/" + request.provider + encodedPath + if (query.isEmpty()) "" else "?$query"
    }
}
