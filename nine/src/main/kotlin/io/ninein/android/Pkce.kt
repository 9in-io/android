package io.ninein.android

import java.security.MessageDigest
import java.security.SecureRandom

/** Base64url without padding (RFC 4648 §5), on every API level (java.util.Base64 needs API 26). */
internal object Base64Url {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val DECODE = IntArray(128) { -1 }.also { table -> ALPHABET.forEachIndexed { i, c -> table[c.code] = i } }

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size * 4 + 2) / 3)
        var i = 0
        while (i + 3 <= bytes.size) {
            val n = (bytes[i].toInt() and 0xff shl 16) or (bytes[i + 1].toInt() and 0xff shl 8) or (bytes[i + 2].toInt() and 0xff)
            out.append(ALPHABET[n ushr 18]).append(ALPHABET[n ushr 12 and 63]).append(ALPHABET[n ushr 6 and 63]).append(ALPHABET[n and 63])
            i += 3
        }
        when (bytes.size - i) {
            1 -> {
                val n = bytes[i].toInt() and 0xff shl 16
                out.append(ALPHABET[n ushr 18]).append(ALPHABET[n ushr 12 and 63])
            }
            2 -> {
                val n = (bytes[i].toInt() and 0xff shl 16) or (bytes[i + 1].toInt() and 0xff shl 8)
                out.append(ALPHABET[n ushr 18]).append(ALPHABET[n ushr 12 and 63]).append(ALPHABET[n ushr 6 and 63])
            }
        }
        return out.toString()
    }

    /** Decodes base64url (padding optional). Throws [IllegalArgumentException] on anything else. */
    fun decode(text: String): ByteArray {
        val s = text.trimEnd('=')
        require(s.length % 4 != 1) { "invalid base64url length" }
        val out = ByteArray(s.length * 3 / 4)
        var buffer = 0
        var bits = 0
        var o = 0
        for (c in s) {
            val v = if (c.code < 128) DECODE[c.code] else -1
            require(v >= 0) { "invalid base64url character" }
            buffer = (buffer shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = (buffer ushr bits and 0xff).toByte()
            }
        }
        // Unused trailing bits must be zero (canonical encoding).
        require(buffer and ((1 shl bits) - 1) == 0) { "non-canonical base64url" }
        return out
    }
}

internal object Crypto {
    val random: SecureRandom by lazy { SecureRandom() }

    /** `bytes` random bytes, base64url-encoded. */
    fun randomString(bytes: Int): String = Base64Url.encode(ByteArray(bytes).also { random.nextBytes(it) })

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** Comparison of two strings in time that depends only on their lengths. */
    fun safeEquals(a: String, b: String): Boolean {
        val x = a.toByteArray(Charsets.UTF_8)
        val y = b.toByteArray(Charsets.UTF_8)
        var diff = x.size xor y.size
        for (i in 0 until maxOf(x.size, y.size)) diff = diff or ((x.getOrElse(i) { 0 }.toInt()) xor (y.getOrElse(i) { 0 }.toInt()))
        return diff == 0
    }
}

/** PKCE (RFC 7636) with the S256 method, the only one 9in accepts. */
public object Pkce {
    /** A new code verifier: 48 random bytes, base64url (64 characters). */
    @JvmStatic
    public fun verifier(): String = Crypto.randomString(48)

    /** `BASE64URL(SHA256(ASCII(verifier)))`. */
    @JvmStatic
    public fun challenge(verifier: String): String = Base64Url.encode(Crypto.sha256(verifier.toByteArray(Charsets.US_ASCII)))
}
