package io.ninein.android

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec

/** A decoded (not yet verified) JWT. */
internal class Jwt(
    val header: Map<String, Any?>,
    val payload: Map<String, Any?>,
    val signingInput: ByteArray,
    val signature: ByteArray,
) {
    companion object {
        fun decode(token: String): Jwt {
            val parts = token.split('.')
            require(parts.size == 3) { "not a JWT" }
            fun json(part: String): Map<String, Any?> {
                @Suppress("UNCHECKED_CAST")
                return Json.parse(Base64Url.decode(part).toString(Charsets.UTF_8)) as? Map<String, Any?>
                    ?: throw IllegalArgumentException("JWT part is not an object")
            }
            return Jwt(json(parts[0]), json(parts[1]), "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII), Base64Url.decode(parts[2]))
        }
    }
}

/**
 * JWS signature checks for the asymmetric algorithms of 9in's key library: RS256/384/512,
 * PS256/384/512, ES256, ES384 and EdDSA (Ed25519). The JWK decides: its `kty` (and curve) must fit
 * the algorithm, and when it names an `alg`, the token must use exactly that one.
 */
internal object Jws {
    private val RSA = mapOf("RS256" to "SHA256withRSA", "RS384" to "SHA384withRSA", "RS512" to "SHA512withRSA")
    private val PSS = mapOf("PS256" to Triple("SHA-256", MGF1ParameterSpec.SHA256, 32), "PS384" to Triple("SHA-384", MGF1ParameterSpec.SHA384, 48), "PS512" to Triple("SHA-512", MGF1ParameterSpec.SHA512, 64))
    private val EC = mapOf("ES256" to Triple("P-256", "secp256r1", "SHA256withECDSA"), "ES384" to Triple("P-384", "secp384r1", "SHA384withECDSA"))
    private val HMAC = setOf("HS256", "HS384", "HS512")

    fun isSupported(alg: String): Boolean = alg in RSA || alg in PSS || alg in EC || alg == "EdDSA"

    fun isHmac(alg: String): Boolean = alg in HMAC

    /** Whether the key may be used to check a signature made with [alg]. */
    fun keyFits(jwk: Map<String, Any?>, alg: String): Boolean {
        val named = jwk.string("alg")
        if (named != null && named != alg) return false
        val use = jwk.string("use")
        if (use != null && use != "sig") return false
        return when {
            alg in RSA || alg in PSS -> jwk.string("kty") == "RSA" && jwk.string("n") != null && jwk.string("e") != null
            alg in EC -> jwk.string("kty") == "EC" && jwk.string("crv") == EC.getValue(alg).first && jwk.string("x") != null && jwk.string("y") != null
            alg == "EdDSA" -> jwk.string("kty") == "OKP" && jwk.string("crv") == "Ed25519" && jwk.string("x") != null
            else -> false
        }
    }

    /** Checks [signature] over [data]. False for a bad signature, a malformed key or an unknown algorithm. */
    fun verify(alg: String, jwk: Map<String, Any?>, data: ByteArray, signature: ByteArray): Boolean {
        if (!keyFits(jwk, alg)) return false
        return try {
            when {
                alg == "EdDSA" -> Ed25519.verify(Base64Url.decode(jwk.string("x")!!), data, signature)
                alg in RSA -> {
                    val key = rsaKey(jwk) ?: return false
                    Signature.getInstance(RSA.getValue(alg)).run {
                        initVerify(key)
                        update(data)
                        verify(signature)
                    }
                }
                alg in PSS -> {
                    val key = rsaKey(jwk) ?: return false
                    verifyPss(PSS.getValue(alg), key, data, signature)
                }
                alg in EC -> {
                    val (_, curve, name) = EC.getValue(alg)
                    val size = if (alg == "ES256") 32 else 48
                    if (signature.size != 2 * size) return false
                    val key = ecKey(jwk, curve, size) ?: return false
                    Signature.getInstance(name).run {
                        initVerify(key)
                        update(data)
                        verify(rawToDer(signature, size))
                    }
                }
                else -> false
            }
        } catch (e: GeneralSecurityException) {
            false
        } catch (e: IllegalArgumentException) {
            false
        }
    }

    private fun unsigned(value: String): BigInteger = BigInteger(1, Base64Url.decode(value))

    private fun rsaKey(jwk: Map<String, Any?>): RSAPublicKey? {
        val n = unsigned(jwk.string("n")!!)
        if (n.bitLength() < 2048) return null // 9in's RSA keys are 2048 or 4096 bits
        return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, unsigned(jwk.string("e")!!))) as RSAPublicKey
    }

    private fun ecKey(jwk: Map<String, Any?>, curve: String, size: Int): PublicKey? {
        val x = BigInteger(1, Base64Url.decode(jwk.string("x")!!).takeIf { it.size == size } ?: return null)
        val y = BigInteger(1, Base64Url.decode(jwk.string("y")!!).takeIf { it.size == size } ?: return null)
        val params = curveParameters(curve)
        if (!onCurve(params, x, y)) return null
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
    }

    private val curves = HashMap<String, ECParameterSpec>()

    /** The named curve's parameters; Android before 8.0 has no `AlgorithmParameters("EC")`, so the standard constants then. */
    @Synchronized
    internal fun curveParameters(curve: String): ECParameterSpec = curves.getOrPut(curve) {
        try {
            AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec(curve)) }.getParameterSpec(ECParameterSpec::class.java)
        } catch (e: GeneralSecurityException) {
            standardCurve(curve)
        }
    }

    /** P-256 and P-384 from SEC 2 / FIPS 186-4. */
    internal fun standardCurve(curve: String): ECParameterSpec {
        fun hex(s: String) = BigInteger(s, 16)
        val (p, a, b, g, n) = when (curve) {
            "secp256r1" -> listOf(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296:4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            )
            "secp384r1" -> listOf(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
                "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
                "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7:3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
            )
            else -> throw IllegalArgumentException("unknown curve $curve")
        }
        val (gx, gy) = g.split(':')
        return ECParameterSpec(EllipticCurve(ECFieldFp(hex(p)), hex(a), hex(b)), ECPoint(hex(gx), hex(gy)), hex(n), 1)
    }

    /** y² = x³ + ax + b (mod p), with coordinates in range. */
    private fun onCurve(params: ECParameterSpec, x: BigInteger, y: BigInteger): Boolean {
        val p = (params.curve.field as ECFieldFp).p
        if (x.signum() < 0 || x >= p || y.signum() < 0 || y >= p) return false
        val right = x.pow(3).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)
        return y.multiply(y).mod(p) == right
    }

    /**
     * RSASSA-PSS with MGF1 of the same hash and a salt as long as the hash. Android names it
     * `SHA256withRSA/PSS`, the JDK `RSASSA-PSS` with parameters. Android 6.0 only has it for
     * Keystore keys, so without a platform implementation the SDK's own [RsaPss] verifies.
     */
    private fun verifyPss(spec: Triple<String, MGF1ParameterSpec, Int>, key: RSAPublicKey, data: ByteArray, signature: ByteArray): Boolean {
        val (hash, mgf, salt) = spec
        val params = PSSParameterSpec(hash, "MGF1", mgf, salt, 1)
        for (name in listOf("RSASSA-PSS", "${hash.replace("-", "")}withRSA/PSS")) {
            try {
                val verifier = Signature.getInstance(name)
                try {
                    verifier.setParameter(params)
                } catch (e: GeneralSecurityException) {
                    // `SHA256withRSA/PSS` has fixed parameters on some providers (the same ones).
                    if (name == "RSASSA-PSS") continue
                } catch (e: UnsupportedOperationException) {
                    if (name == "RSASSA-PSS") continue
                }
                verifier.initVerify(key)
                verifier.update(data)
                return verifier.verify(signature)
            } catch (e: GeneralSecurityException) {
                // Not available for software keys here: try the next name, then our own.
            }
        }
        return RsaPss.verify(key, hash, data, signature)
    }

    /** JWS ECDSA signatures are r‖s; java.security wants ASN.1 DER. */
    internal fun rawToDer(raw: ByteArray, size: Int): ByteArray {
        fun integer(bytes: ByteArray): ByteArray {
            var start = 0
            while (start < bytes.size - 1 && bytes[start].toInt() == 0) start++
            val trimmed = bytes.copyOfRange(start, bytes.size)
            val body = if (trimmed[0].toInt() and 0x80 != 0) byteArrayOf(0) + trimmed else trimmed
            return byteArrayOf(0x02, body.size.toByte()) + body
        }
        val r = integer(raw.copyOfRange(0, size))
        val s = integer(raw.copyOfRange(size, 2 * size))
        val content = r + s
        val length = if (content.size < 128) byteArrayOf(content.size.toByte()) else byteArrayOf(0x81.toByte(), content.size.toByte())
        return byteArrayOf(0x30) + length + content
    }
}

/**
 * RSASSA-PSS verification (RFC 8017 §8.1.2 and EMSA-PSS-VERIFY, §9.1.2) with MGF1 of the same hash
 * and a salt as long as the hash, for Android versions without a platform implementation for
 * software keys. Only public values are involved.
 */
internal object RsaPss {
    fun verify(key: RSAPublicKey, hash: String, message: ByteArray, signature: ByteArray): Boolean {
        val n = key.modulus
        val modBits = n.bitLength()
        val k = (modBits + 7) / 8
        if (signature.size != k) return false
        val s = BigInteger(1, signature)
        if (s >= n) return false
        val m = s.modPow(key.publicExponent, n)
        val emBits = modBits - 1
        val emLen = (emBits + 7) / 8
        val em = toBytes(m, emLen) ?: return false
        return emsaPssVerify(hash, message, em, emBits)
    }

    private fun toBytes(value: BigInteger, length: Int): ByteArray? {
        val raw = value.toByteArray()
        val start = raw.indexOfFirst { it.toInt() != 0 }.let { if (it < 0) raw.size else it }
        val trimmed = raw.copyOfRange(start, raw.size)
        if (trimmed.size > length) return null
        return ByteArray(length - trimmed.size) + trimmed
    }

    private fun emsaPssVerify(hash: String, message: ByteArray, em: ByteArray, emBits: Int): Boolean {
        val digest = MessageDigest.getInstance(hash)
        val hLen = digest.digestLength
        val sLen = hLen
        val emLen = em.size
        if (emLen < hLen + sLen + 2) return false
        if (em[emLen - 1] != 0xbc.toByte()) return false
        val mHash = digest.digest(message)
        val maskedDb = em.copyOfRange(0, emLen - hLen - 1)
        val h = em.copyOfRange(emLen - hLen - 1, emLen - 1)
        val unusedBits = 8 * emLen - emBits
        val topMask = (0xff ushr unusedBits)
        if (maskedDb[0].toInt() and topMask.inv() and 0xff != 0) return false
        val dbMask = mgf1(hash, h, maskedDb.size)
        val db = ByteArray(maskedDb.size) { (maskedDb[it].toInt() xor dbMask[it].toInt()).toByte() }
        db[0] = (db[0].toInt() and topMask).toByte()
        val padding = emLen - hLen - sLen - 2
        for (i in 0 until padding) if (db[i].toInt() != 0) return false
        if (db[padding].toInt() != 1) return false
        val salt = db.copyOfRange(db.size - sLen, db.size)
        digest.reset()
        digest.update(ByteArray(8))
        digest.update(mHash)
        digest.update(salt)
        return MessageDigest.isEqual(h, digest.digest())
    }

    private fun mgf1(hash: String, seed: ByteArray, length: Int): ByteArray {
        val digest = MessageDigest.getInstance(hash)
        val out = ByteArray(length)
        var offset = 0
        var counter = 0
        while (offset < length) {
            digest.update(seed)
            digest.update(byteArrayOf((counter ushr 24).toByte(), (counter ushr 16).toByte(), (counter ushr 8).toByte(), counter.toByte()))
            val block = digest.digest()
            val n = minOf(block.size, length - offset)
            System.arraycopy(block, 0, out, offset, n)
            offset += n
            counter++
        }
        return out
    }
}
