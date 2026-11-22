package io.ninein.android

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/** An HTTP request made by the SDK. */
public class HttpRequest(
    public val method: String,
    public val url: String,
    public val headers: Map<String, String> = emptyMap(),
    public val body: ByteArray? = null,
)

/** An HTTP response. Header names are lower-case. */
public class HttpResponse(
    public val status: Int,
    public val headers: Map<String, List<String>> = emptyMap(),
    public val body: ByteArray = ByteArray(0),
) {
    public val text: String get() = body.toString(Charsets.UTF_8)
}

/**
 * How the SDK talks to 9in. The default is [UrlConnectionTransport]; pass your own (for example
 * on top of OkHttp) to [NineClient] to share a connection pool or add certificate pinning.
 *
 * [execute] is called on a background thread and may block. It must not follow redirects, and it
 * should throw [IOException] when the server can't be reached.
 */
public fun interface HttpTransport {
    @Throws(IOException::class)
    public fun execute(request: HttpRequest): HttpResponse
}

/**
 * [HttpTransport] on `HttpURLConnection`: 10 s connect and 15 s read timeouts, no redirects,
 * no caching, responses up to 1 MB.
 */
public class UrlConnectionTransport @JvmOverloads constructor(
    private val connectTimeoutMillis: Int = 10_000,
    private val readTimeoutMillis: Int = 15_000,
) : HttpTransport {
    override fun execute(request: HttpRequest): HttpResponse {
        val connection = URL(request.url).openConnection() as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = connectTimeoutMillis
            connection.readTimeout = readTimeoutMillis
            connection.requestMethod = request.method
            connection.setRequestProperty("User-Agent", USER_AGENT)
            for ((name, value) in request.headers) connection.setRequestProperty(name, value)
            val body = request.body
            if (body != null) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val bytes = stream?.use { readLimited(it) } ?: ByteArray(0)
            val headers = connection.headerFields
                .filterKeys { it != null }
                .mapKeys { it.key.lowercase() }
            return HttpResponse(status, headers, bytes)
        } finally {
            connection.disconnect()
        }
    }

    private fun readLimited(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            out.write(buffer, 0, n)
            if (out.size() > MAX_BODY) throw IOException("response larger than $MAX_BODY bytes")
        }
        return out.toByteArray()
    }

    private companion object {
        const val MAX_BODY = 1 shl 20
    }
}

internal const val USER_AGENT: String = "9in-android/${Nine.VERSION}"

internal fun formEncode(form: Map<String, String>): String =
    form.entries.joinToString("&") { (k, v) -> "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}" }

/** Appends query parameters to a URL that may already have a query. */
internal fun withQuery(url: String, params: Map<String, String>): String {
    if (params.isEmpty()) return url
    val hash = url.indexOf('#')
    val base = if (hash >= 0) url.substring(0, hash) else url
    val separator = if (base.contains('?')) (if (base.endsWith("?") || base.endsWith("&")) "" else "&") else "?"
    return base + separator + formEncode(params) + (if (hash >= 0) url.substring(hash) else "")
}
