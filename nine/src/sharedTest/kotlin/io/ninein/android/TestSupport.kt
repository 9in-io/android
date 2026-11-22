package io.ninein.android

import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Assert.fail

/** A clock tests can move. */
internal class TestClock(@Volatile var now: Long = System.currentTimeMillis()) : java.time.Clock() {
    override fun millis(): Long = now
    override fun instant(): java.time.Instant = java.time.Instant.ofEpochMilli(now)
    override fun getZone(): java.time.ZoneId = java.time.ZoneOffset.UTC
    override fun withZone(zone: java.time.ZoneId?): java.time.Clock = this
    fun advance(seconds: Long) {
        now += seconds * 1000
    }
}

internal const val REDIRECT = "com.acme.app:/callback"

internal fun FakeNine.client(
    store: CredentialStore = MemoryCredentialStore(),
    clock: java.time.Clock = java.time.Clock.systemUTC(),
    scopes: List<String> = NineConfig.DEFAULT_SCOPES,
    audience: String? = null,
    locale: String? = null,
): NineClient = NineClient(NineConfig(issuer, clientId, REDIRECT, scopes, audience, locale), store, this, Dispatchers.IO, clock)

/** Changes one character in the middle of a JWT's signature. */
internal fun tamper(token: String): String {
    val i = token.lastIndexOf('.') + 10
    return token.substring(0, i) + (if (token[i] == 'A') 'B' else 'A') + token.substring(i + 1)
}

internal inline fun expectNine(code: String, block: () -> Unit): NineException {
    try {
        block()
    } catch (e: NineException) {
        assertEquals("${e.message}", code, e.code)
        return e
    }
    fail("expected NineException $code")
    throw AssertionError()
}
