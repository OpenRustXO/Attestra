package dev.attestra.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

class HttpRequest(
    val method: String,
    val url: String,
    val headers: Map<String, String> = emptyMap(),
    val body: ByteArray? = null,
)

class HttpResponse(
    val status: Int,
    val headers: Map<String, List<String>>,
    val body: ByteArray,
)

/** Performs HTTP requests; injectable for tests or to plug in OkHttp. */
fun interface HttpTransport {
    suspend fun execute(request: HttpRequest): HttpResponse
}

/** A dependency-free transport on top of [HttpURLConnection]. Responses are buffered. */
class UrlConnectionTransport(
    private val connectTimeoutMillis: Int = 15_000,
    private val readTimeoutMillis: Int = 60_000,
) : HttpTransport {
    override suspend fun execute(request: HttpRequest): HttpResponse = withContext(Dispatchers.IO) {
        val connection = URL(request.url).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = request.method
            connection.connectTimeout = connectTimeoutMillis
            connection.readTimeout = readTimeoutMillis
            connection.instanceFollowRedirects = false
            request.headers.forEach { (name, value) -> connection.setRequestProperty(name, value) }
            request.body?.let { body ->
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val body = stream?.use { it.readBytes() } ?: ByteArray(0)
            val headers = connection.headerFields.filterKeys { it != null }.mapKeys { it.key.lowercase() }
            HttpResponse(status, headers, body)
        } finally {
            connection.disconnect()
        }
    }
}
