package io.ninein.android

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class SignInTest {
    private lateinit var fake: FakeNine

    @Before
    fun setUp() {
        AuthorizationBroker.reset()
        fake = FakeNine()
    }

    @Test
    fun `signs in with PKCE, state and nonce and stores the tokens`() = runBlocking<Unit> {
        val store = MemoryCredentialStore()
        val nine = fake.client(store)
        val user = nine.signIn(fake.browser())
        assertEquals("usr_alice", user.id)
        assertEquals("alice@acme.test", user.email)
        assertEquals(true, user.emailVerified)
        assertEquals(listOf("pwd"), user.authenticationMethods)
        assertEquals(AuthState.SignedIn(user), nine.state.value)
        assertTrue(nine.isSignedIn)
        assertEquals(user, nine.user)

        val exchange = fake.requests.single { it.url() == fake.tokenEndpoint }
        val form = FakeNine.form(exchange)
        assertEquals("authorization_code", form["grant_type"])
        assertEquals(REDIRECT, form["redirect_uri"])
        assertEquals("app_test", form["client_id"])
        assertTrue(Regex("^[A-Za-z0-9_-]{64}$").matches(form["code_verifier"]!!))
        assertNull("public clients never send a secret", exchange.header("Authorization"))

        val credentials = nine.credentials()!!
        assertNotNull(credentials.refreshToken)
        assertNotNull(credentials.idToken)
        assertEquals(listOf("openid", "profile", "email", "offline_access"), credentials.scopes)
        // Tokens and the finished sign-in are stored; nothing is left pending.
        assertEquals(setOf("9in:${fake.issuer}:app_test:credentials", "9in:${fake.issuer}:app_test:obtained_at"), store.keys())
    }

    @Test
    fun `the authorization request carries everything 9in needs`() = runBlocking<Unit> {
        val nine = fake.client(audience = "https://api.acme.test", locale = "de")
        nine.signIn(fake.browser(), SignInOptions(prompt = "login", loginHint = "alice@acme.test", maxAgeSeconds = 600, extraParams = mapOf("state" to "evil", "redirect_uri" to "https://evil", "acr_values" to "x")))
        val p = fake.authorizeRequests.last()
        assertEquals("code", p["response_type"])
        assertEquals("app_test", p["client_id"])
        assertEquals(REDIRECT, p["redirect_uri"])
        assertEquals("openid profile email offline_access", p["scope"])
        assertEquals("S256", p["code_challenge_method"])
        assertEquals("https://api.acme.test", p["audience"])
        assertEquals("login", p["prompt"])
        assertEquals("alice@acme.test", p["login_hint"])
        assertEquals("600", p["max_age"])
        assertEquals("de", p["ui_locales"])
        assertEquals("x", p["acr_values"])
        assertTrue("extra params never replace state", p["state"] != "evil" && p["state"]!!.length >= 32)
        assertTrue(p["nonce"]!!.length >= 32)

        nine.signUp(fake.browser(), SignInOptions(locale = "fr"))
        val signup = fake.authorizeRequests.last()
        assertEquals("create", signup["prompt"])
        assertEquals("fr", signup["ui_locales"])
        assertTrue("every sign-in has its own state", signup["state"] != p["state"])
        assertTrue(signup["code_challenge"] != p["code_challenge"])
    }

    @Test
    fun `a redirect with another state is refused and the sign-in stays open`() = runBlocking<Unit> {
        val nine = fake.client()
        var real: String? = null
        expectNine(NineException.INVALID_STATE) {
            nine.signIn(BrowserStep { url, _ -> fake.authorize(url).also { real = it }.replace(Regex("state=[^&]+"), "state=forged") })
        }
        assertEquals(AuthState.SignedOut, nine.state.value)
        // The forged redirect did not use up the sign-in: the real one still completes it, once.
        assertEquals("usr_alice", nine.handleRedirect(real!!).id)
        expectNine(NineException.INVALID_STATE) { nine.handleRedirect(real!!) }
    }

    @Test
    fun `a redirect without state, or with no sign-in in progress, is refused`() = runBlocking<Unit> {
        val nine = fake.client()
        expectNine(NineException.INVALID_STATE) { nine.signIn(fake.browser { it.replace(Regex("state=[^&]+&?"), "") }) }
        expectNine(NineException.INVALID_STATE) { fake.client().handleRedirect("$REDIRECT?code=abc&state=xyz&iss=${fake.issuer}") }
    }

    @Test
    fun `a replayed redirect is refused`() = runBlocking<Unit> {
        val nine = fake.client()
        var callback: String? = null
        nine.signIn(fake.browser { it.also { callback = it } })
        expectNine(NineException.INVALID_STATE) { nine.handleRedirect(callback!!) }
    }

    @Test
    fun `a sign-in that took too long is refused`() = runBlocking<Unit> {
        val clock = TestClock()
        val nine = fake.client(clock = clock)
        expectNine(NineException.INVALID_STATE) {
            nine.signIn(BrowserStep { url, _ -> fake.authorize(url).also { clock.advance(16 * 60) } })
        }
    }

    @Test
    fun `the RFC 9207 issuer must be ours, and present when advertised`() = runBlocking<Unit> {
        expectNine(NineException.INVALID_ISSUER) { fake.client().signIn(fake.browser { it.replace(Regex("iss=[^&]+"), "iss=https%3A%2F%2Fevil.example") }) }
        expectNine(NineException.INVALID_ISSUER) { fake.client().signIn(fake.browser { it.replace(Regex("&iss=[^&]+"), "") }) }
        // A trailing slash is the same issuer.
        fake.client().signIn(fake.browser { it.replace(Regex("iss=[^&]+"), "iss=https%3A%2F%2Facme.9in.test%2F") })
        // Servers that don't advertise the parameter may leave it out.
        fake.issParameterSupported = false
        fake.client().signIn(fake.browser { it.replace(Regex("&iss=[^&]+"), "") })
    }

    @Test
    fun `errors from 9in are reported with their code, after the state check`() = runBlocking<Unit> {
        val denied = expectNine("access_denied") {
            fake.client().signIn(BrowserStep { url, _ ->
                val state = queryParams(url)["state"]
                "$REDIRECT?error=access_denied&error_description=The+user+declined&state=$state&iss=${fake.issuer}"
            })
        }
        assertEquals("The user declined", denied.description)
        expectNine(NineException.INVALID_STATE) {
            fake.client().signIn(BrowserStep { _, _ -> "$REDIRECT?error=access_denied&state=other&iss=${fake.issuer}" })
        }
        expectNine(NineException.MISSING_CODE) {
            fake.client().signIn(BrowserStep { url, _ -> "$REDIRECT?state=${queryParams(url)["state"]}&iss=${fake.issuer}" })
        }
    }

    @Test
    fun `a refused code exchange is an OAuth error with the HTTP status`() = runBlocking<Unit> {
        val e = expectNine(NineException.INVALID_GRANT) { fake.client().signIn(fake.browser { it.replace(Regex("code=[^&]+"), "code=wrong") }) }
        assertEquals(400, e.status)
        assertEquals("invalid or expired code", e.description)
    }

    @Test
    fun `ID tokens signed with every algorithm of the key library are accepted`() = runBlocking<Unit> {
        for (alg in TestKey.ALGORITHMS) {
            fake.key = TestKey(alg)
            val nine = fake.client()
            assertEquals(alg, "usr_alice", nine.signIn(fake.browser()).id)
        }
    }

    /** The Java core verifies ID tokens (tested there); here: a refused one fails the sign-in and stores nothing. */
    private fun idTokenRejected(case: String, setup: () -> Unit) = runBlocking<Unit> {
        val f = FakeNine().also { fake = it }
        setup()
        val nine = f.client()
        val e = expectNine(NineException.INVALID_ID_TOKEN) { nine.signIn(f.browser()) }
        assertTrue("$case: ${e.description}", e.description.isNotEmpty())
        assertTrue("$case: the core's error is the cause", e is io.ninein.NineException)
        assertEquals("$case: a refused sign-in stores nothing", null, nine.credentials())
        assertEquals(AuthState.SignedOut, nine.state.value)
    }

    @Test
    fun `ID tokens that fail the core's checks fail the sign-in`() {
        idTokenRejected("nonce") { fake.idTokenClaims = { it["nonce"] = "other" } }
        idTokenRejected("audience") { fake.idTokenClaims = { it["aud"] = "app_other"; it["azp"] = null } }
        idTokenRejected("azp") { fake.idTokenClaims = { it["azp"] = "app_other" } }
        idTokenRejected("issuer") { fake.idTokenClaims = { it["iss"] = "https://evil.example" } }
        idTokenRejected("expired") { fake.idTokenClaims = { it["exp"] = System.currentTimeMillis() / 1000 - 400 } }
        idTokenRejected("typ") { fake.idTokenHeader = mapOf("typ" to "at+jwt") }
        idTokenRejected("signature") { fake.idTokenOverride = { tamper(fake.idToken(null)) } }
        idTokenRejected("forged under a known kid") {
            val forger = TestKey("RS256", kid = fake.key.kid)
            fake.idTokenOverride = { fake.idToken(null, signer = forger) }
        }
        idTokenRejected("alg none") {
            fake.idTokenOverride = { TestKey.unsigned(mapOf("alg" to "none", "kid" to fake.key.kid), mapOf("iss" to fake.issuer, "sub" to "x", "aud" to "app_test")) }
        }
        idTokenRejected("alg not the key's") { fake.idTokenHeader = mapOf("alg" to "RS512") }
        idTokenRejected("unknown kid") { fake.idTokenHeader = mapOf("kid" to "k_unknown") }
        idTokenRejected("missing ID token") { fake.tokenResponse = { it.remove("id_token") } }
    }

    @Test
    fun `the device clock tolerance reaches the core`() = runBlocking<Unit> {
        // 9in's ID tokens checked with NineConfig.clockSkewSeconds (300 s by default, for phones
        // whose clock is a little off), not the core's server default of 30 s.
        fake.idTokenClaims = { it["exp"] = System.currentTimeMillis() / 1000 - 100; it["iat"] = System.currentTimeMillis() / 1000 + 100 }
        assertEquals("usr_alice", fake.client().signIn(fake.browser()).id)
        val strict = NineClient(NineConfig(fake.issuer, fake.clientId, REDIRECT, clockSkewSeconds = 10), MemoryCredentialStore(), fake, kotlinx.coroutines.Dispatchers.IO, java.time.Clock.systemUTC())
        expectNine(NineException.INVALID_ID_TOKEN) { strict.signIn(fake.browser()) }
    }

    @Test
    fun `several audiences are fine when azp is this app`() = runBlocking<Unit> {
        fake.idTokenClaims = { it["aud"] = listOf("https://api.acme.test", "app_test") }
        assertEquals("usr_alice", fake.client().signIn(fake.browser()).id)
    }

    @Test
    fun `a new signing key is found after a rotation`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        fake.key = TestKey("ES256") // a new default key with a new kid
        assertEquals("usr_alice", nine.signIn(fake.browser()).id)
        assertEquals(2, fake.jwksCalls.get())
    }

    @Test
    fun `without the openid scope there is no ID token and no claims`() = runBlocking<Unit> {
        val nine = fake.client(scopes = listOf("offline_access"))
        val user = nine.signIn(fake.browser())
        assertEquals("", user.id)
        assertTrue(nine.isSignedIn)
        assertNull(nine.credentials()!!.idToken)
    }

    @Test
    fun `discovery is fetched once and must be for our issuer`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        nine.refresh()
        nine.userInfo()
        nine.signOut()
        assertEquals(1, fake.discoveryCalls.get())

        fake.discoveryOverrides = mapOf("issuer" to "https://evil.example")
        expectNine(NineException.INVALID_ISSUER) { fake.client().signIn(fake.browser()) }
        fake.discoveryOverrides = mapOf("token_endpoint" to "http://acme.9in.test/oauth/token")
        expectNine(NineException.DISCOVERY_FAILED) { fake.client().signIn(fake.browser()) }
        fake.discoveryOverrides = mapOf("token_endpoint" to null)
        expectNine(NineException.DISCOVERY_FAILED) { fake.client().signIn(fake.browser()) }
        fake.discoveryOverrides = emptyMap()
        fake.discoveryStatus = 503
        assertEquals(503, expectNine(NineException.DISCOVERY_FAILED) { fake.client().signIn(fake.browser()) }.status)
    }

    @Test
    fun `network failures are network_error`() = runBlocking<Unit> {
        fake.failNetwork = true
        expectNine(NineException.NETWORK_ERROR) { fake.client().signIn(fake.browser()) }
    }

    @Test
    fun `closing the browser cancels the sign-in and forgets it`() = runBlocking<Unit> {
        val store = MemoryCredentialStore()
        val nine = fake.client(store)
        expectNine(NineException.CANCELED) { nine.signIn(BrowserStep { _, _ -> throw NineException(NineException.CANCELED) }) }
        assertEquals(emptySet<String>(), store.keys())
        assertEquals(AuthState.SignedOut, nine.state.value)
    }

    @Test
    fun `a newer sign-in replaces an older one`() = runBlocking<Unit> {
        val nine = fake.client()
        var first: String? = null
        expectNine(NineException.CANCELED) {
            nine.signIn(BrowserStep { url, _ ->
                first = fake.authorize(url)
                throw NineException(NineException.CANCELED)
            })
        }
        // The canceled sign-in's redirect no longer completes anything.
        expectNine(NineException.INVALID_STATE) { nine.handleRedirect(first!!) }
        assertEquals("usr_alice", nine.signIn(fake.browser()).id)
    }
}
