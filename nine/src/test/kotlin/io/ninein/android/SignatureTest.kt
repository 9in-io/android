package io.ninein.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class Ed25519Test {
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // RFC 8032 §7.1, tests 1–3 and SHA(abc).
    private val vectors = listOf(
        Triple(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        Triple(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        Triple(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        Triple(
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    )

    @Test
    fun `RFC 8032 vectors verify`() {
        for ((pub, msg, sig) in vectors) assertTrue(Ed25519.verify(hex(pub), hex(msg), hex(sig)))
    }

    @Test
    fun `tampered messages, signatures and keys fail`() {
        val (pub, msg, sig) = vectors[2]
        assertFalse(Ed25519.verify(hex(pub), hex("af83"), hex(sig)))
        for (i in listOf(0, 31, 32, 63)) {
            val bad = hex(sig).also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertFalse(Ed25519.verify(hex(pub), hex(msg), bad))
        }
        assertFalse(Ed25519.verify(hex(vectors[0].first), hex(msg), hex(sig)))
        assertFalse(Ed25519.verify(hex(pub).copyOf(31), hex(msg), hex(sig)))
        assertFalse(Ed25519.verify(hex(pub), hex(msg), hex(sig).copyOf(63)))
    }

    @Test
    fun `S at or above the group order is rejected (malleability)`() {
        val (pub, msg, sig) = vectors[1]
        val l = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
        val bytes = hex(sig)
        val s = BigInteger(1, bytes.copyOfRange(32, 64).reversedArray()).add(l)
        val sBytes = s.toByteArray().reversedArray().copyOf(32)
        assertFalse(Ed25519.verify(hex(pub), hex(msg), bytes.copyOfRange(0, 32) + sBytes))
    }

    @Test
    fun `non-canonical or invalid points are rejected`() {
        val (_, msg, sig) = vectors[0]
        // y = p (not reduced), and y = 1 with the sign bit set (x = 0 can't be negative).
        val p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
        assertFalse(Ed25519.verify(p.toByteArray().reversedArray().copyOf(32), hex(msg), hex(sig)))
        assertFalse(Ed25519.verify(ByteArray(32) { if (it == 0) 1 else if (it == 31) 0x80.toByte() else 0 }, hex(msg), hex(sig)))
    }

    @Test
    fun `agrees with the JDK on random messages`() {
        val key = TestKey("EdDSA")
        val pub = Base64Url.decode(key.jwk()["x"] as String)
        repeat(20) { n ->
            val msg = ByteArray(n * 13) { (it * n).toByte() }
            val sig = key.sign(msg)
            assertTrue(Ed25519.verify(pub, msg, sig))
            assertFalse(Ed25519.verify(pub, msg + byteArrayOf(1), sig))
        }
    }
}

/** Signs with the JDK and verifies with [Jws] for every algorithm; also run under Robolectric (Conscrypt). */
internal fun checkEveryAlgorithm() {
    val data = "header.payload".toByteArray()
    for (alg in TestKey.ALGORITHMS) {
            val key = TestKey(alg)
            val sig = key.sign(data)
            assertTrue(alg, Jws.verify(alg, key.jwk(), data, sig))
            assertTrue("$alg without alg in the JWK", Jws.verify(alg, key.jwk(withAlg = false), data, sig))
            assertFalse("$alg tampered data", Jws.verify(alg, key.jwk(), "header.payloaD".toByteArray(), sig))
            val bad = sig.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x10).toByte() }
            assertFalse("$alg tampered signature", Jws.verify(alg, key.jwk(), data, bad))
            assertFalse("$alg other key", Jws.verify(alg, TestKey(alg).jwk(), data, sig))
    }
}

@org.junit.runner.RunWith(org.robolectric.RobolectricTestRunner::class)
@org.robolectric.annotation.Config(sdk = [24, 37])
class JwsOnAndroidTest {
    @Test
    fun `every algorithm verifies with Android's security providers`() {
        checkEveryAlgorithm()
    }
}

class RsaPssTest {
    private val data = "header.payload".toByteArray()

    @Test
    fun `the built-in RSASSA-PSS verifier agrees with the JDK`() {
        for (bits in listOf(2048, 4096)) {
            for (alg in listOf("PS256", "PS384", "PS512")) {
                val key = TestKey(alg, rsaBits = bits)
                val public = key.pair.public as java.security.interfaces.RSAPublicKey
                val hash = "SHA-" + alg.substring(2)
                repeat(3) { i ->
                    val message = data + ByteArray(i * 50) { it.toByte() }
                    val sig = key.sign(message)
                    assertTrue("$alg/$bits", RsaPss.verify(public, hash, message, sig))
                    assertFalse("$alg/$bits tampered message", RsaPss.verify(public, hash, message + 1, sig))
                    for (pos in listOf(0, sig.size / 2, sig.size - 1)) {
                        val bad = sig.copyOf().also { it[pos] = (it[pos].toInt() xor 0x04).toByte() }
                        assertFalse("$alg/$bits tampered signature at $pos", RsaPss.verify(public, hash, message, bad))
                    }
                    assertFalse("$alg/$bits other hash", RsaPss.verify(public, if (hash == "SHA-256") "SHA-384" else "SHA-256", message, sig))
                }
            }
        }
    }

    private fun craft(key: TestKey, message: ByteArray, trailer: Int = 0xbc, separator: Int = 1, padByte: Int = 0) =
        key.pssSignRaw(message, "SHA-256", trailer, separator, padByte)

    @Test
    fun `the encoding is checked, not only the hash`() {
        val key = TestKey("PS256")
        val public = key.pair.public as java.security.interfaces.RSAPublicKey
        assertTrue("a correct hand-made encoding verifies", RsaPss.verify(public, "SHA-256", data, craft(key, data)))
        assertTrue("and the JDK agrees", java.security.Signature.getInstance("RSASSA-PSS").run {
            setParameter(java.security.spec.PSSParameterSpec("SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 32, 1))
            initVerify(public); update(data); verify(craft(key, data))
        })
        assertFalse("trailer must be 0xbc", RsaPss.verify(public, "SHA-256", data, craft(key, data, trailer = 0xbb)))
        assertFalse("separator must be 0x01", RsaPss.verify(public, "SHA-256", data, craft(key, data, separator = 2)))
        assertFalse("padding must be zero", RsaPss.verify(public, "SHA-256", data, craft(key, data, padByte = 1)))
    }

    @Test
    fun `malformed signatures are refused`() {
        val key = TestKey("PS256")
        val public = key.pair.public as java.security.interfaces.RSAPublicKey
        val sig = key.sign(data)
        assertFalse(RsaPss.verify(public, "SHA-256", data, sig.copyOf(sig.size - 1)))
        assertFalse(RsaPss.verify(public, "SHA-256", data, byteArrayOf(0) + sig))
        assertFalse(RsaPss.verify(public, "SHA-256", data, ByteArray(sig.size) { 0xff.toByte() })) // s >= n
        assertFalse(RsaPss.verify(public, "SHA-256", data, ByteArray(sig.size)))
        // A PKCS#1 v1.5 signature is not a PSS signature.
        val pkcs1 = java.security.Signature.getInstance("SHA256withRSA").run { initSign(key.pair.private); update(data); sign() }
        assertFalse(RsaPss.verify(public, "SHA-256", data, pkcs1))
    }
}

class JwsTest {
    private val data = "header.payload".toByteArray()

    @Test
    fun `every algorithm of the key library verifies`() = checkEveryAlgorithm()

    @Test
    fun `4096-bit RSA keys verify`() {
        val key = TestKey("PS512", rsaBits = 4096)
        assertTrue(Jws.verify("PS512", key.jwk(), data, key.sign(data)))
    }

    @Test
    fun `the key decides the algorithm`() {
        val rs = TestKey("RS256")
        // A JWK that names RS256 can't check a PS256 or RS512 signature, even with the same RSA key.
        assertFalse(Jws.keyFits(rs.jwk(), "PS256"))
        assertFalse(Jws.keyFits(rs.jwk(), "RS512"))
        assertFalse(Jws.verify("RS512", rs.jwk(), data, rs.sign(data)))
        // Key types must fit: an EC key for RS256, an RSA key for ES256, a P-384 key for ES256, an Ed25519 key for ES256.
        assertFalse(Jws.keyFits(TestKey("ES256").jwk(withAlg = false), "RS256"))
        assertFalse(Jws.keyFits(rs.jwk(withAlg = false), "ES256"))
        assertFalse(Jws.keyFits(TestKey("ES384").jwk(withAlg = false), "ES256"))
        assertFalse(Jws.keyFits(TestKey("EdDSA").jwk(withAlg = false), "ES256"))
        assertFalse(Jws.keyFits(rs.jwk() + ("use" to "enc"), "RS256"))
        assertTrue(Jws.keyFits(rs.jwk(), "RS256"))
    }

    @Test
    fun `none, HMAC and unknown algorithms are not supported`() {
        for (alg in listOf("none", "HS256", "HS384", "HS512", "ES512", "RSA-OAEP", "")) assertFalse(alg, Jws.isSupported(alg))
        assertTrue(Jws.isHmac("HS256"))
        assertFalse(Jws.verify("none", mapOf("kty" to "RSA"), data, ByteArray(0)))
    }

    @Test
    fun `small RSA keys and malformed keys are refused`() {
        val small = TestKey("RS256", rsaBits = 1024)
        assertFalse(Jws.verify("RS256", small.jwk(), data, small.sign(data)))
        val ec = TestKey("ES256")
        assertFalse(Jws.verify("ES256", ec.jwk() + ("x" to "AAAA"), data, ec.sign(data)))
        assertFalse(Jws.verify("ES256", ec.jwk(), data, ec.sign(data).copyOf(63)))
        assertFalse(Jws.verify("RS256", TestKey("RS256").jwk() + ("n" to "!!"), data, ByteArray(256)))
    }

    @Test
    fun `the built-in curve constants are the JDK's named curves`() {
        for (curve in listOf("secp256r1", "secp384r1")) {
            val named = java.security.AlgorithmParameters.getInstance("EC").apply { init(java.security.spec.ECGenParameterSpec(curve)) }
                .getParameterSpec(java.security.spec.ECParameterSpec::class.java)
            val ours = Jws.standardCurve(curve)
            assertEquals(curve, named.curve, ours.curve)
            assertEquals(curve, named.generator, ours.generator)
            assertEquals(curve, named.order, ours.order)
            assertEquals(curve, named.cofactor, ours.cofactor)
        }
        // And keys built with them verify.
        val key = TestKey("ES384")
        val point = (key.pair.public as java.security.interfaces.ECPublicKey).w
        val public = java.security.KeyFactory.getInstance("EC").generatePublic(java.security.spec.ECPublicKeySpec(point, Jws.standardCurve("secp384r1")))
        val sig = java.security.Signature.getInstance("SHA384withECDSA").run { initSign(key.pair.private); update(data); sign() }
        assertTrue(java.security.Signature.getInstance("SHA384withECDSA").run { initVerify(public); update(data); verify(sig) })
    }

    @Test
    fun `EC points off the curve are refused`() {
        val key = TestKey("ES256")
        val jwk = key.jwk()
        val y = BigInteger(1, Base64Url.decode(jwk["y"] as String)).add(BigInteger.ONE)
        assertFalse(Jws.verify("ES256", jwk + ("y" to TestKey.b64(y, 32)), data, key.sign(data)))
    }

    @Test
    fun `ECDSA raw signatures convert to DER`() {
        val raw = ByteArray(64) { if (it == 0 || it == 32) 0x80.toByte() else 1 }
        val der = Jws.rawToDer(raw, 32)
        assertEquals(0x30, der[0].toInt())
        assertArrayEquals(raw, TestKey.derToRaw(der, 32))
        val zeros = ByteArray(64).also { it[31] = 5; it[63] = 7 }
        assertArrayEquals(zeros, TestKey.derToRaw(Jws.rawToDer(zeros, 32), 32))
        val big = ByteArray(96) { 0xff.toByte() }
        assertArrayEquals(big, TestKey.derToRaw(Jws.rawToDer(big, 48), 48))
    }
}
