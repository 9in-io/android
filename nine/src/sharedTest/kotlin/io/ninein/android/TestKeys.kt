package io.ninein.android

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/** Keys for every asymmetric algorithm of 9in's key library, made with the JDK, and JWTs signed with them. */
internal class TestKey(val alg: String, val kid: String = "k_${alg.lowercase()}_${Crypto.randomString(4)}", rsaBits: Int = 2048) {
    val pair: KeyPair = when {
        alg.startsWith("RS") || alg.startsWith("PS") -> KeyPairGenerator.getInstance("RSA").apply { initialize(rsaBits) }.generateKeyPair()
        alg == "ES256" -> KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        alg == "ES384" -> KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        alg == "EdDSA" -> KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        else -> error("no key for $alg")
    }

    /** The public JWK, as 9in publishes it (with `alg` unless [withAlg] is false). */
    fun jwk(withAlg: Boolean = true): Map<String, Any?> {
        val base = when (val key = pair.public) {
            is RSAPublicKey -> mapOf("kty" to "RSA", "n" to b64(key.modulus), "e" to b64(key.publicExponent))
            is ECPublicKey -> {
                val size = if (alg == "ES256") 32 else 48
                mapOf("kty" to "EC", "crv" to if (alg == "ES256") "P-256" else "P-384", "x" to b64(key.w.affineX, size), "y" to b64(key.w.affineY, size))
            }
            else -> mapOf("kty" to "OKP", "crv" to "Ed25519", "x" to Base64Url.encode(key.encoded.copyOfRange(key.encoded.size - 32, key.encoded.size)))
        }
        return base + mapOf("kid" to kid, "use" to "sig") + (if (withAlg) mapOf("alg" to alg) else emptyMap())
    }

    fun sign(data: ByteArray): ByteArray = when {
        alg.startsWith("RS") -> Signature.getInstance("SHA${alg.substring(2)}withRSA").run {
            initSign(pair.private); update(data); sign()
        }
        alg.startsWith("PS") -> {
            val bits = alg.substring(2)
            // The JDK calls it RSASSA-PSS; Android SHA256withRSA/PSS (salt = hash length, MGF1 with the same hash).
            try {
                val signer = try {
                    Signature.getInstance("RSASSA-PSS").apply { setParameter(PSSParameterSpec("SHA-$bits", "MGF1", MGF1ParameterSpec("SHA-$bits"), bits.toInt() / 8, 1)) }
                } catch (e: java.security.GeneralSecurityException) {
                    Signature.getInstance("SHA${bits}withRSA/PSS")
                }
                signer.run { initSign(pair.private); update(data); sign() }
            } catch (e: java.security.GeneralSecurityException) {
                pssSignRaw(data, "SHA-$bits") // Android 6.0 signs PSS only with Keystore keys
            }
        }
        alg.startsWith("ES") -> {
            val der = Signature.getInstance("SHA${alg.substring(2)}withECDSA").run { initSign(pair.private); update(data); sign() }
            derToRaw(der, if (alg == "ES256") 32 else 48)
        }
        else -> Signature.getInstance("Ed25519").run { initSign(pair.private); update(data); sign() }
    }

    /**
     * EMSA-PSS-ENCODE (RFC 8017 §9.1.1, salt as long as the hash) and the raw RSA private-key
     * operation, for platforms without a PSS signer; the damage options make malformed encodings.
     */
    fun pssSignRaw(message: ByteArray, hash: String, trailer: Int = 0xbc, separator: Int = 1, padByte: Int = 0): ByteArray {
        val public = pair.public as RSAPublicKey
        val private = pair.private as java.security.interfaces.RSAPrivateKey
        val md = java.security.MessageDigest.getInstance(hash)
        val hLen = md.digestLength
        val emBits = public.modulus.bitLength() - 1
        val emLen = (emBits + 7) / 8
        val salt = ByteArray(hLen) { (it * 7 + 1).toByte() }
        val mHash = md.digest(message)
        md.update(ByteArray(8)); md.update(mHash); md.update(salt)
        val h = md.digest()
        val db = ByteArray(emLen - hLen - 1)
        db[db.size - hLen - 1] = separator.toByte()
        if (padByte != 0) db[0] = padByte.toByte()
        System.arraycopy(salt, 0, db, db.size - hLen, hLen)
        val mask = ByteArray(db.size)
        var off = 0
        var counter = 0
        while (off < mask.size) {
            md.update(h); md.update(byteArrayOf(0, 0, (counter ushr 8).toByte(), counter.toByte()))
            val block = md.digest()
            val n = minOf(block.size, mask.size - off)
            System.arraycopy(block, 0, mask, off, n)
            off += n; counter++
        }
        val masked = ByteArray(db.size) { (db[it].toInt() xor mask[it].toInt()).toByte() }
        masked[0] = (masked[0].toInt() and (0xff ushr (8 * emLen - emBits))).toByte()
        val em = masked + h + byteArrayOf(trailer.toByte())
        val sig = BigInteger(1, em).modPow(private.privateExponent, public.modulus).toByteArray()
        val k = (public.modulus.bitLength() + 7) / 8
        return if (sig.size > k) sig.copyOfRange(sig.size - k, sig.size) else ByteArray(k - sig.size) + sig
    }

    /** A signed JWT. [header] entries override the defaults (alg, kid, typ). */
    fun jwt(payload: Map<String, Any?>, header: Map<String, Any?> = emptyMap()): String {
        val h = linkedMapOf<String, Any?>("alg" to alg, "kid" to kid, "typ" to "JWT").apply { putAll(header) }.filterValues { it != null }
        val input = "${Base64Url.encode(Json.stringify(h).toByteArray())}.${Base64Url.encode(Json.stringify(payload).toByteArray())}"
        return "$input.${Base64Url.encode(sign(input.toByteArray()))}"
    }

    companion object {
        val ALGORITHMS = listOf("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA")

        fun b64(value: BigInteger, size: Int = 0): String {
            var bytes = value.toByteArray()
            if (bytes.size > 1 && bytes[0].toInt() == 0) bytes = bytes.copyOfRange(1, bytes.size)
            if (bytes.size < size) bytes = ByteArray(size - bytes.size) + bytes
            return Base64Url.encode(bytes)
        }

        /** ASN.1 DER ECDSA signature → JWS r‖s. */
        fun derToRaw(der: ByteArray, size: Int): ByteArray {
            var i = 2
            if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7f
            fun int(): ByteArray {
                check(der[i].toInt() == 0x02)
                val len = der[i + 1].toInt()
                var v = der.copyOfRange(i + 2, i + 2 + len)
                i += 2 + len
                while (v.size > size && v[0].toInt() == 0) v = v.copyOfRange(1, v.size)
                return ByteArray(size - v.size) + v
            }
            return int() + int()
        }

        /** An unsigned JWT with the given header (for `alg: none` and friends). */
        fun unsigned(header: Map<String, Any?>, payload: Map<String, Any?>, signature: String = ""): String =
            "${Base64Url.encode(Json.stringify(header).toByteArray())}.${Base64Url.encode(Json.stringify(payload).toByteArray())}.$signature"
    }
}
