package io.ninein.android

import java.math.BigInteger
import java.security.MessageDigest

/**
 * Ed25519 signature verification (RFC 8032 §5.1.7) in plain Kotlin. Android only gained a
 * platform Ed25519 implementation in recent releases, and 9in tenants may sign with an EdDSA key,
 * so the SDK carries its own verifier: it only checks signatures (no secret keys involved), so it
 * does not need to be constant-time.
 */
internal object Ed25519 {
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val L: BigInteger = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
    private val D: BigInteger = BigInteger.valueOf(-121665).mod(P).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
    private val TWO_D: BigInteger = D.shiftLeft(1).mod(P)
    private val SQRT_M1: BigInteger = BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)
    private val TWO = BigInteger.valueOf(2)

    /** A point in extended coordinates: x = X/Z, y = Y/Z, x*y = T/Z. */
    private class Point(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger)

    private val IDENTITY = Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)
    private val BASE: Point = run {
        val y = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P)
        val x = recoverX(y, 0) ?: error("Ed25519 base point")
        Point(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        val a = decode(publicKey) ?: return false
        val rBytes = signature.copyOfRange(0, 32)
        val r = decode(rBytes) ?: return false
        val s = littleEndian(signature.copyOfRange(32, 64))
        if (s >= L) return false
        val digest = MessageDigest.getInstance("SHA-512").run {
            update(rBytes)
            update(publicKey)
            update(message)
            digest()
        }
        val k = littleEndian(digest).mod(L)
        val left = multiply(BASE, s)
        val right = add(r, multiply(a, k))
        return equal(left, right)
    }

    private fun littleEndian(bytes: ByteArray): BigInteger = BigInteger(1, bytes.reversedArray())

    private fun recoverX(y: BigInteger, sign: Int): BigInteger? {
        if (y >= P) return null
        val y2 = y.multiply(y).mod(P)
        val u = y2.subtract(BigInteger.ONE).mod(P)
        val v = D.multiply(y2).add(BigInteger.ONE).mod(P)
        val x2 = u.multiply(v.modInverse(P)).mod(P)
        if (x2.signum() == 0) return if (sign == 1) null else BigInteger.ZERO
        var x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P)
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) x = x.multiply(SQRT_M1).mod(P)
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) return null
        if (x.testBit(0) != (sign == 1)) x = P.subtract(x)
        return x
    }

    private fun decode(bytes: ByteArray): Point? {
        val copy = bytes.copyOf()
        val sign = (copy[31].toInt() ushr 7) and 1
        copy[31] = (copy[31].toInt() and 0x7f).toByte()
        val y = littleEndian(copy)
        val x = recoverX(y, sign) ?: return null
        return Point(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    // RFC 8032 §5.1.4, a = -1.
    private fun add(p: Point, q: Point): Point {
        val a = p.y.subtract(p.x).multiply(q.y.subtract(q.x)).mod(P)
        val b = p.y.add(p.x).multiply(q.y.add(q.x)).mod(P)
        val c = p.t.multiply(TWO_D).multiply(q.t).mod(P)
        val d = p.z.multiply(TWO).multiply(q.z).mod(P)
        val e = b.subtract(a)
        val f = d.subtract(c)
        val g = d.add(c)
        val h = b.add(a)
        return Point(e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P))
    }

    private fun multiply(point: Point, scalar: BigInteger): Point {
        var result = IDENTITY
        for (i in scalar.bitLength() - 1 downTo 0) {
            result = add(result, result)
            if (scalar.testBit(i)) result = add(result, point)
        }
        return result
    }

    private fun equal(p: Point, q: Point): Boolean =
        p.x.multiply(q.z).subtract(q.x.multiply(p.z)).mod(P).signum() == 0 &&
            p.y.multiply(q.z).subtract(q.y.multiply(p.z)).mod(P).signum() == 0
}
