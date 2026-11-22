package io.ninein.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PkceTest {
    @Test
    fun `RFC 7636 appendix B example`() {
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
    }

    @Test
    fun `verifiers are 64 unreserved characters and unique`() {
        val seen = HashSet<String>()
        repeat(200) {
            val v = Pkce.verifier()
            assertTrue(v, Regex("^[A-Za-z0-9_-]{64}$").matches(v))
            assertTrue(seen.add(v))
        }
        // What 9in accepts as a challenge.
        assertTrue(Regex("^[A-Za-z0-9_-]{43,128}$").matches(Pkce.challenge(Pkce.verifier())))
    }
}

class Base64UrlTest {
    @Test
    fun `round trips every length`() {
        for (n in 0..64) {
            val bytes = ByteArray(n) { (it * 37 + n).toByte() }
            val encoded = Base64Url.encode(bytes)
            assertFalse(encoded.contains('=') || encoded.contains('+') || encoded.contains('/'))
            assertArrayEquals(bytes, Base64Url.decode(encoded))
            assertEquals(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes), encoded)
        }
    }

    @Test
    fun `accepts padding and rejects junk`() {
        assertArrayEquals("f".toByteArray(), Base64Url.decode("Zg=="))
        assertThrows(IllegalArgumentException::class.java) { Base64Url.decode("Zm9v+") }
        assertThrows(IllegalArgumentException::class.java) { Base64Url.decode("Z") }
        assertThrows(IllegalArgumentException::class.java) { Base64Url.decode("Zm9v/w") }
        assertThrows(IllegalArgumentException::class.java) { Base64Url.decode("Zh") } // non-canonical trailing bits
    }
}

class JsonTest {
    @Test
    fun `parses objects, arrays and scalars`() {
        @Suppress("UNCHECKED_CAST")
        val v = Json.parse("""{"a":1,"b":-2.5e1,"c":"x\"\\\/\n\u00e9\ud83d\ude00","d":[true,false,null],"e":{},"f":[],"g":12345678901234}""") as Map<String, Any?>
        assertEquals(1L, v["a"])
        assertEquals(-25.0, v["b"])
        assertEquals("x\"\\/\né😀", v["c"])
        assertEquals(listOf(true, false, null), v["d"])
        assertEquals(emptyMap<String, Any?>(), v["e"])
        assertEquals(emptyList<Any?>(), v["f"])
        assertEquals(12345678901234L, v["g"])
        assertEquals(listOf("a", "b", "c", "d", "e", "f", "g"), v.keys.toList())
    }

    @Test
    fun `rejects malformed input`() {
        for (bad in listOf("", "{", "{\"a\"}", "{\"a\":1,}", "[1,]", "01", "1.", "-", "\"\u0001\"", "{\"a\":1} x", "tru", "'a'", "{a:1}", "\"\\x\"", "NaN")) {
            assertThrows(bad, IllegalArgumentException::class.java) { Json.parse(bad) }
        }
        assertThrows(IllegalArgumentException::class.java) { Json.parse("[".repeat(100) + "]".repeat(100)) }
        val e = assertThrows(NineException::class.java) { Json.parseObject("[1]") }
        assertEquals(NineException.INVALID_RESPONSE, e.code)
        assertEquals(NineException.INVALID_RESPONSE, assertThrows(NineException::class.java) { Json.parseObject("<html>") }.code)
    }

    @Test
    fun `writes JSON that parses back`() {
        val value = linkedMapOf("s" to "a\"b\\c\n\u0001\u2028", "n" to 3L, "d" to 1.5, "whole" to 2.0, "b" to true, "z" to null, "l" to listOf(1, "x"), "m" to mapOf("k" to "v"))
        val text = Json.stringify(value)
        assertEquals("""{"s":"a\"b\\c\n\u0001\u2028","n":3,"d":1.5,"whole":2,"b":true,"z":null,"l":[1,"x"],"m":{"k":"v"}}""", text)
        assertEquals(mapOf("s" to "a\"b\\c\n\u0001\u2028", "n" to 3L, "d" to 1.5, "whole" to 2L, "b" to true, "z" to null, "l" to listOf(1L, "x"), "m" to mapOf("k" to "v")), Json.parse(text))
    }
}

class IssuerTest {
    private fun code(issuer: String, allow: Boolean = false) = assertThrows(NineException::class.java) { Issuer.normalize(issuer, allow) }.code

    @Test
    fun `https issuers are accepted and lose a trailing slash`() {
        assertEquals("https://acme.9in.io", Issuer.normalize("https://acme.9in.io/"))
        assertEquals("https://login.acme.com", Issuer.normalize("https://login.acme.com"))
        assertEquals("https://acme.9in.io/tenant", Issuer.normalize("https://acme.9in.io/tenant/"))
    }

    @Test
    fun `plain http only for localhost and loopback`() {
        for (ok in listOf("http://localhost:8787", "http://auth.localhost", "http://127.0.0.1:9000", "http://127.1.2.3", "http://[::1]:8080")) {
            assertEquals(ok, Issuer.normalize(ok))
        }
        for (bad in listOf("http://acme.9in.io", "http://10.0.2.2:8787", "http://localhost.evil.com", "ftp://acme.9in.io")) {
            assertEquals(bad, NineException.INSECURE_ISSUER, code(bad))
        }
        assertEquals("http://auth:8897", Issuer.normalize("http://auth:8897", allowInsecure = true))
    }

    @Test
    fun `queries, fragments, credentials and non-URLs are rejected`() {
        for (bad in listOf("https://acme.9in.io?x=1", "https://acme.9in.io#a", "https://user:pw@acme.9in.io", "acme.9in.io", "not a url", "https://")) {
            assertEquals(bad, NineException.INVALID_ISSUER, code(bad))
        }
    }

    @Test
    fun `config validates its arguments`() {
        assertEquals(NineException.INVALID_OPTIONS, assertThrows(NineException::class.java) { NineConfig("https://a.9in.io", "", "com.acme.app:/cb") }.code)
        assertEquals(NineException.INVALID_OPTIONS, assertThrows(NineException::class.java) { NineConfig("https://a.9in.io", "app", "") }.code)
        assertEquals(NineException.INVALID_OPTIONS, assertThrows(NineException::class.java) { NineConfig("https://a.9in.io", "app", "no scheme") }.code)
        assertEquals(NineException.INVALID_OPTIONS, assertThrows(NineException::class.java) { NineConfig("https://a.9in.io", "app", "com.acme.app:/cb#x") }.code)
        assertEquals(NineException.INVALID_OPTIONS, assertThrows(NineException::class.java) { NineConfig("https://a.9in.io", "app", "com.acme.app:/cb", scopes = listOf("openid profile")) }.code)
        assertEquals(NineException.INSECURE_ISSUER, assertThrows(NineException::class.java) { NineConfig("http://a.9in.io", "app", "com.acme.app:/cb") }.code)
        assertEquals("https://a.9in.io", NineConfig("https://a.9in.io/", "app", "com.acme.app:/cb").issuer)
    }

    @Test
    fun `constant-time comparison`() {
        assertTrue(Crypto.safeEquals("abc", "abc"))
        assertFalse(Crypto.safeEquals("abc", "abd"))
        assertFalse(Crypto.safeEquals("abc", "abcd"))
        assertFalse(Crypto.safeEquals("", "a"))
        assertTrue(Crypto.safeEquals("", ""))
    }

    @Test
    fun `query parameters of redirects`() {
        assertEquals(mapOf("code" to "a b", "state" to "x+y", "iss" to "https://a.9in.io"), OidcClient.queryParams("com.acme.app:/cb?code=a+b&state=x%2By&iss=https%3A%2F%2Fa.9in.io#frag"))
        assertEquals(mapOf("state" to "first"), OidcClient.queryParams("https://app/cb?state=first&state=second"))
        assertEquals(emptyMap<String, String>(), OidcClient.queryParams("com.acme.app:/cb"))
        assertNull(OidcClient.queryParams("com.acme.app:/cb?state=%zz")["state"])
        assertEquals("https://a/x?b=1&c=d+e", withQuery("https://a/x?b=1", mapOf("c" to "d e")))
        assertEquals("https://a/x?c=d#f", withQuery("https://a/x#f", mapOf("c" to "d")))
    }
}
