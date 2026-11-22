package io.ninein.android

/**
 * A small, strict JSON reader and writer (RFC 8259), so the protocol core needs no JSON library
 * and behaves the same on the JVM and on every Android version.
 *
 * Values are `Map<String, Any?>` (insertion-ordered), `List<Any?>`, `String`, `Long` (integers that
 * fit), `Double` (other numbers), `Boolean` and `null`.
 */
/** A small JSON reader and writer for the tests (the SDK itself uses the Java core's). */
internal object Json {
    private const val MAX_DEPTH = 64

    fun parse(text: String): Any? {
        val reader = Reader(text)
        reader.skipWhitespace()
        val value = reader.readValue(0)
        reader.skipWhitespace()
        if (!reader.atEnd()) throw reader.error("unexpected trailing characters")
        return value
    }

    /** Parses a JSON object. */
    fun parseObject(text: String): Map<String, Any?> {
        val value = try {
            parse(text)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("malformed JSON", e)
        }
        @Suppress("UNCHECKED_CAST")
        return value as? Map<String, Any?> ?: throw IllegalArgumentException("expected a JSON object")
    }

    fun stringify(value: Any?): String = StringBuilder().also { write(it, value) }.toString()

    private fun write(out: StringBuilder, value: Any?) {
        when (value) {
            null -> out.append("null")
            is String -> writeString(out, value)
            is Boolean -> out.append(value)
            is Int, is Long, is Short, is Byte -> out.append(value.toString())
            is Double -> {
                require(value.isFinite()) { "JSON cannot represent $value" }
                if (value == Math.rint(value) && Math.abs(value) < 1e15) out.append(value.toLong()) else out.append(value)
            }
            is Float -> write(out, value.toDouble())
            is Number -> out.append(value.toString())
            is Map<*, *> -> {
                out.append('{')
                var first = true
                for ((k, v) in value) {
                    if (!first) out.append(',')
                    first = false
                    writeString(out, k.toString())
                    out.append(':')
                    write(out, v)
                }
                out.append('}')
            }
            is Iterable<*> -> {
                out.append('[')
                var first = true
                for (v in value) {
                    if (!first) out.append(',')
                    first = false
                    write(out, v)
                }
                out.append(']')
            }
            is Array<*> -> write(out, value.asList())
            else -> writeString(out, value.toString())
        }
    }

    private fun writeString(out: StringBuilder, s: String) {
        out.append('"')
        for (c in s) {
            when (c) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                else -> if (c < ' ' || c == ' ' || c == ' ') {
                    out.append("\\u").append(String.format("%04x", c.code))
                } else {
                    out.append(c)
                }
            }
        }
        out.append('"')
    }

    private class Reader(private val s: String) {
        private var i = 0

        fun atEnd() = i >= s.length

        fun error(message: String) = IllegalArgumentException("$message at offset $i")

        fun skipWhitespace() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) i++
        }

        fun readValue(depth: Int): Any? {
            if (depth > MAX_DEPTH) throw error("nesting too deep")
            if (atEnd()) throw error("unexpected end")
            return when (val c = s[i]) {
                '{' -> readObject(depth)
                '[' -> readArray(depth)
                '"' -> readString()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c in '0'..'9') readNumber() else throw error("unexpected character '$c'")
            }
        }

        private fun literal(word: String, value: Any?): Any? {
            if (!s.startsWith(word, i)) throw error("invalid literal")
            i += word.length
            return value
        }

        private fun readObject(depth: Int): Map<String, Any?> {
            i++ // {
            val map = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (i < s.length && s[i] == '}') {
                i++
                return map
            }
            while (true) {
                skipWhitespace()
                if (atEnd() || s[i] != '"') throw error("expected a property name")
                val key = readString()
                skipWhitespace()
                if (atEnd() || s[i] != ':') throw error("expected ':'")
                i++
                skipWhitespace()
                map[key] = readValue(depth + 1)
                skipWhitespace()
                if (atEnd()) throw error("unexpected end")
                when (s[i]) {
                    ',' -> i++
                    '}' -> {
                        i++
                        return map
                    }
                    else -> throw error("expected ',' or '}'")
                }
            }
        }

        private fun readArray(depth: Int): List<Any?> {
            i++ // [
            val list = ArrayList<Any?>()
            skipWhitespace()
            if (i < s.length && s[i] == ']') {
                i++
                return list
            }
            while (true) {
                skipWhitespace()
                list.add(readValue(depth + 1))
                skipWhitespace()
                if (atEnd()) throw error("unexpected end")
                when (s[i]) {
                    ',' -> i++
                    ']' -> {
                        i++
                        return list
                    }
                    else -> throw error("expected ',' or ']'")
                }
            }
        }

        private fun readString(): String {
            i++ // opening quote
            val out = StringBuilder()
            while (true) {
                if (atEnd()) throw error("unterminated string")
                val c = s[i++]
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> {
                        if (atEnd()) throw error("unterminated escape")
                        when (val e = s[i++]) {
                            '"' -> out.append('"')
                            '\\' -> out.append('\\')
                            '/' -> out.append('/')
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                if (i + 4 > s.length) throw error("short unicode escape")
                                var code = 0
                                repeat(4) {
                                    val d = Character.digit(s[i++], 16)
                                    if (d < 0) throw error("bad unicode escape")
                                    code = code * 16 + d
                                }
                                out.append(code.toChar())
                            }
                            else -> throw error("bad escape '\\$e'")
                        }
                    }
                    c < ' ' -> throw error("control character in string")
                    else -> out.append(c)
                }
            }
        }

        private fun readNumber(): Any {
            val start = i
            if (s[i] == '-') i++
            if (atEnd()) throw error("bad number")
            if (s[i] == '0') {
                i++
            } else if (s[i] in '1'..'9') {
                while (i < s.length && s[i] in '0'..'9') i++
            } else {
                throw error("bad number")
            }
            var integral = true
            if (i < s.length && s[i] == '.') {
                integral = false
                i++
                if (atEnd() || s[i] !in '0'..'9') throw error("bad fraction")
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                integral = false
                i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                if (atEnd() || s[i] !in '0'..'9') throw error("bad exponent")
                while (i < s.length && s[i] in '0'..'9') i++
            }
            val text = s.substring(start, i)
            if (integral) text.toLongOrNull()?.let { return it }
            return text.toDouble()
        }
    }
}

// Typed accessors for parsed JSON objects.

internal fun Map<String, Any?>.string(key: String): String? = this[key] as? String

internal fun Map<String, Any?>.long(key: String): Long? = when (val v = this[key]) {
    is Long -> v
    is Int -> v.toLong()
    is Double -> if (v.isFinite() && v == Math.rint(v)) v.toLong() else null
    else -> null
}

// Small helpers the tests share (the SDK's own copies live in the Java core).

internal object Base64Url {
    fun encode(bytes: ByteArray): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun decode(text: String): ByteArray = java.util.Base64.getUrlDecoder().decode(text)
}

internal object Crypto {
    private val random = java.security.SecureRandom()
    fun randomString(bytes: Int): String = Base64Url.encode(ByteArray(bytes).also { random.nextBytes(it) })
}

internal fun formEncode(form: Map<String, String>): String =
    form.entries.joinToString("&") { (k, v) -> "${java.net.URLEncoder.encode(k, "UTF-8")}=${java.net.URLEncoder.encode(v, "UTF-8")}" }

internal fun withQuery(url: String, params: Map<String, String>): String =
    if (params.isEmpty()) url else url + (if (url.contains('?')) "&" else "?") + formEncode(params)

/** Query parameters of a URL (decoded; the first value wins). */
internal fun queryParams(url: String): Map<String, String> {
    val params = LinkedHashMap<String, String>()
    for (pair in url.substringBefore('#').substringAfter('?', "").split('&')) {
        if (pair.isEmpty()) continue
        val eq = pair.indexOf('=')
        val name = java.net.URLDecoder.decode(if (eq >= 0) pair.substring(0, eq) else pair, "UTF-8")
        if (name !in params) params[name] = if (eq >= 0) java.net.URLDecoder.decode(pair.substring(eq + 1), "UTF-8") else ""
    }
    return params
}

/** The payload of a JWT, unverified (for assertions). */
@Suppress("UNCHECKED_CAST")
internal fun jwtPart(token: String, part: Int): Map<String, Any?> =
    Json.parse(String(Base64Url.decode(token.split('.')[part]), Charsets.UTF_8)) as Map<String, Any?>
