package io.ninein.android

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

class NineClientTest {
    private lateinit var fake: FakeNine

    @Before
    fun setUp() {
        AuthorizationBroker.reset()
        fake = FakeNine()
    }

    private fun tokenCalls(grant: String) = fake.requests.count { it.url == fake.tokenEndpoint && FakeNine.form(it)["grant_type"] == grant }

    @Test
    fun `a fresh access token is returned without calling 9in`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        val before = fake.requests.size
        assertEquals(nine.credentials()!!.accessToken, nine.accessToken())
        assertEquals(before, fake.requests.size)
    }

    @Test
    fun `an expiring access token is refreshed and the rotated refresh token kept`() = runBlocking<Unit> {
        val clock = TestClock()
        val store = MemoryCredentialStore()
        val nine = fake.client(store, clock)
        nine.signIn(fake.browser())
        val old = nine.credentials()!!
        clock.advance(3600 - 30) // within the 60 s margin
        val token = nine.accessToken()
        val new = nine.credentials()!!
        assertNotEquals(old.accessToken, token)
        assertEquals(new.accessToken, token)
        assertNotEquals("rotated", old.refreshToken, new.refreshToken)
        assertNotEquals(old.idToken, new.idToken)
        assertFalse(fake.isRefreshTokenValid(old.refreshToken!!))
        assertTrue(fake.isRefreshTokenValid(new.refreshToken!!))
        // The stored copy is the new one, so a restarted app uses the right refresh token.
        assertEquals(new.refreshToken, Credentials.fromJson(store.read("9in:${fake.issuer}:app_test:credentials")!!)!!.refreshToken)
        assertEquals("refreshed without the client id? no", "app_test", FakeNine.form(fake.requests.last { it.url == fake.tokenEndpoint })["client_id"])
        assertEquals("usr_alice", nine.user!!.id)
        // A custom margin.
        assertEquals(token, nine.accessToken(minValiditySeconds = 0))
        assertEquals(1, tokenCalls("refresh_token"))
    }

    @Test
    fun `short-lived access tokens are not refreshed on every call`() = runBlocking<Unit> {
        val clock = TestClock()
        fake.accessTokenLifetime = 60 // the shortest lifetime 9in allows
        val nine = fake.client(clock = clock)
        nine.signIn(fake.browser())
        val first = nine.accessToken()
        clock.advance(20)
        assertEquals(first, nine.accessToken())
        assertEquals(0, fake.refreshCalls.get())
        clock.advance(15) // within half the lifetime of expiry
        assertNotEquals(first, nine.accessToken())
        assertEquals(1, fake.refreshCalls.get())
    }

    @Test
    fun `a store that fails after a refresh still keeps the new refresh token in memory`() = runBlocking<Unit> {
        var failWrites = false
        val inner = MemoryCredentialStore()
        val store = object : CredentialStore {
            override fun read(key: String) = inner.read(key)
            override fun write(key: String, value: String?) {
                if (failWrites && value != null) throw IllegalStateException("disk full")
                inner.write(key, value)
            }
        }
        val nine = fake.client(store)
        nine.signIn(fake.browser())
        val old = nine.credentials()!!.refreshToken!!
        failWrites = true
        expectNine(NineException.STORAGE_ERROR) { nine.refresh() }
        val kept = nine.credentials()!!.refreshToken!!
        assertNotEquals(old, kept)
        assertTrue(fake.isRefreshTokenValid(kept))
        failWrites = false
        assertNotNull(nine.refresh()) // works with the token that was kept
    }

    @Test
    fun `a refresh that finishes late does not overwrite a newer sign-in`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        val release = java.util.concurrent.CountDownLatch(1)
        val entered = java.util.concurrent.CountDownLatch(1)
        fake.beforeRefresh = { entered.countDown(); release.await() }
        val refresh = async(Dispatchers.IO) { runCatching { nine.refresh() } }
        entered.await()
        val signIn = async(Dispatchers.IO) { nine.signIn(BrowserStep { url, _ -> fake.authorize(url, signedInAs = "usr_bob") }) }
        Thread.sleep(300) // the sign-in now waits for the refresh to finish
        fake.subject = "usr_alice" // the refresh is still for alice's session
        release.countDown()
        refresh.await()
        assertEquals("usr_bob", signIn.await().id)
        assertEquals("usr_bob", nine.user!!.id)
    }

    @Test
    fun `a refresh without a new refresh token keeps the old one`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        val old = nine.credentials()!!
        fake.omitRefreshTokenOnRefresh = true
        fake.tokenResponse = { it.remove("id_token") }
        val new = nine.refresh()
        assertEquals(old.refreshToken, new.refreshToken)
        assertEquals(old.idToken, new.idToken)
        assertNotEquals(old.accessToken, new.accessToken)
    }

    @Test
    fun `concurrent callers share one refresh`() = runBlocking<Unit> {
        val clock = TestClock()
        val nine = fake.client(clock = clock)
        nine.signIn(fake.browser())
        clock.advance(3600)
        fake.beforeRefresh = { Thread.sleep(300) }
        val tokens = (1..25).map { async(Dispatchers.IO) { nine.accessToken() } }.awaitAll()
        assertEquals(1, tokens.toSet().size)
        assertEquals(1, fake.refreshCalls.get())
        assertEquals(nine.credentials()!!.accessToken, tokens.first())
    }

    @Test
    fun `a revoked refresh token signs the user out`() = runBlocking<Unit> {
        val store = MemoryCredentialStore()
        val nine = fake.client(store)
        nine.signIn(fake.browser())
        fake.endSessions()
        val e = expectNine(NineException.LOGIN_REQUIRED) { nine.refresh() }
        assertEquals(NineException.INVALID_GRANT, (e.cause as NineException).code)
        assertEquals(AuthState.SignedOut, nine.state.value)
        assertNull(nine.credentials())
        assertEquals(emptySet<String>(), store.keys())
        expectNine(NineException.LOGIN_REQUIRED) { nine.accessToken() }
    }

    @Test
    fun `a network failure during refresh keeps the session`() = runBlocking<Unit> {
        val clock = TestClock()
        val nine = fake.client(clock = clock)
        nine.signIn(fake.browser())
        clock.advance(3600)
        fake.failNetwork = true
        expectNine(NineException.NETWORK_ERROR) { nine.accessToken() }
        assertTrue(nine.isSignedIn)
        fake.failNetwork = false
        assertNotNull(nine.accessToken())
    }

    @Test
    fun `server errors during refresh keep the session`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        fake.refreshError = "temporarily_unavailable"
        expectNine("temporarily_unavailable") { nine.refresh() }
        assertTrue(nine.isSignedIn)
    }

    @Test
    fun `a refreshed ID token must be for the same user and valid`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        fake.subject = "usr_mallory"
        val e = expectNine(NineException.INVALID_ID_TOKEN) { nine.refresh() }
        assertEquals("the ID token is for another user", e.description)
        assertEquals(AuthState.SignedOut, nine.state.value)

        val again = fake.client()
        again.signIn(fake.browser())
        fake.idTokenOverride = { tamper(fake.idToken(null)) }
        expectNine(NineException.INVALID_ID_TOKEN) { again.refresh() }
        assertFalse(again.isSignedIn)
    }

    @Test
    fun `refreshed ID tokens carry no nonce and are accepted`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        fake.email = "alice@new.test"
        nine.refresh()
        assertEquals("alice@new.test", nine.user!!.email)
        assertNull(nine.user!!["nonce"])
    }

    @Test
    fun `without a refresh token an expired session ends`() = runBlocking<Unit> {
        val clock = TestClock()
        val nine = fake.client(clock = clock, scopes = listOf("openid", "email"))
        nine.signIn(fake.browser())
        assertNull(nine.credentials()!!.refreshToken)
        expectNine(NineException.LOGIN_REQUIRED) { nine.refresh() }
        assertTrue(nine.isSignedIn)
        // Within the refresh margin the token still works: there is nothing to refresh it with.
        clock.advance(3600 - 30)
        assertEquals(nine.credentials()!!.accessToken, nine.accessToken())
        clock.advance(30)
        expectNine(NineException.LOGIN_REQUIRED) { nine.accessToken() }
        assertFalse(nine.isSignedIn)
    }

    @Test
    fun `nobody signed in`() = runBlocking<Unit> {
        val nine = fake.client()
        assertEquals(AuthState.SignedOut, nine.state.first { it != AuthState.Loading })
        expectNine(NineException.LOGIN_REQUIRED) { nine.accessToken() }
        expectNine(NineException.LOGIN_REQUIRED) { nine.refresh() }
        expectNine(NineException.LOGIN_REQUIRED) { nine.userInfo() }
        assertNull(nine.credentials())
        assertNull(nine.user)
    }

    @Test
    fun `the session survives an app restart`() = runBlocking<Unit> {
        val store = MemoryCredentialStore()
        val user = fake.client(store).signIn(fake.browser())
        val restarted = fake.client(store)
        assertEquals(AuthState.SignedIn(user), restarted.state.first { it != AuthState.Loading })
        assertNotNull(restarted.accessToken())
        assertEquals("usr_alice", restarted.userInfo()["sub"])
    }

    @Test
    fun `a stored session that can't be used is dropped on start`() = runBlocking<Unit> {
        val clock = TestClock()
        val store = MemoryCredentialStore()
        fake.client(store, clock, scopes = listOf("openid")).signIn(fake.browser())
        clock.advance(7200)
        val later = fake.client(store, clock, scopes = listOf("openid"))
        assertEquals(AuthState.SignedOut, later.state.first { it != AuthState.Loading })
        assertEquals(emptySet<String>(), store.keys())

        store.write("9in:${fake.issuer}:app_test:credentials", "{not json")
        assertEquals(AuthState.SignedOut, fake.client(store).state.first { it != AuthState.Loading })

        val broken = object : CredentialStore {
            override fun read(key: String): String? = throw IllegalStateException("keystore unavailable")
            override fun write(key: String, value: String?) = Unit
        }
        assertEquals(AuthState.SignedOut, fake.client(broken).state.first { it != AuthState.Loading })
    }

    @Test
    fun `state goes from loading to signed out, signed in and signed out`() = runBlocking<Unit> {
        val nine = fake.client()
        val seen = mutableListOf<AuthState>()
        val job = launch(Dispatchers.Unconfined) { nine.state.collect { seen.add(it) } }
        nine.signIn(fake.browser())
        nine.signOut()
        job.cancelAndJoin()
        assertEquals(listOf("SignedOut", "SignedIn", "SignedOut"), seen.filter { it != AuthState.Loading }.map { it.javaClass.simpleName })
    }

    @Test
    fun `signing out revokes the refresh token and forgets everything`() = runBlocking<Unit> {
        val store = MemoryCredentialStore()
        val nine = fake.client(store)
        nine.signIn(fake.browser())
        val refresh = nine.credentials()!!.refreshToken!!
        nine.signOut()
        assertEquals(mapOf("token" to refresh, "token_type_hint" to "refresh_token", "client_id" to "app_test"), fake.revoked.single())
        assertFalse(fake.isRefreshTokenValid(refresh))
        assertEquals(AuthState.SignedOut, nine.state.value)
        assertEquals(emptySet<String>(), store.keys())
    }

    @Test
    fun `signing out in the browser ends the 9in session`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        val idToken = nine.credentials()!!.idToken!!
        var opened: Pair<String, String>? = null
        nine.signOut(BrowserStep { url, redirect -> opened = url to redirect; "$redirect?state=" }, postLogoutRedirectUri = REDIRECT)
        val (url, redirect) = opened!!
        assertTrue(url.startsWith("${fake.issuer}/oauth/logout?"))
        val p = OidcClient.queryParams(url)
        assertEquals("app_test", p["client_id"])
        assertEquals(idToken, p["id_token_hint"])
        assertEquals(REDIRECT, p["post_logout_redirect_uri"])
        assertEquals(REDIRECT, redirect)

        // Closing the "signed out" page is fine; the user is signed out either way.
        val again = fake.client()
        again.signIn(fake.browser())
        again.signOut(BrowserStep { url2, _ ->
            assertNull(OidcClient.queryParams(url2)["post_logout_redirect_uri"])
            throw NineException(NineException.CANCELED)
        })
        assertFalse(again.isSignedIn)
    }

    @Test
    fun `signing out works offline and without a session`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        fake.failNetwork = true
        nine.signOut()
        assertFalse(nine.isSignedIn)
        fake.failNetwork = false
        nine.signOut() // nobody signed in: nothing to revoke
        assertEquals(0, fake.revoked.size)
    }

    @Test
    fun `userinfo uses the access token`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        val info = nine.userInfo()
        assertEquals("usr_alice", info["sub"])
        val call = fake.requests.last()
        assertEquals("Bearer ${nine.credentials()!!.accessToken}", call.headers["Authorization"])
        fake.endSessions()
        assertEquals(401, expectNine(NineException.INVALID_TOKEN) { nine.userInfo() }.status)
    }

    @Test
    fun `tokens never appear in toString`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.signIn(fake.browser())
        val c = nine.credentials()!!
        val text = c.toString() + nine.state.value.toString() + nine.user.toString()
        for (secret in listOfNotNull(c.accessToken, c.refreshToken, c.idToken)) assertFalse(text.contains(secret))
    }

    @Test
    fun `credentials round trip through JSON`() {
        val c = Credentials("at", "Bearer", 123, "rt", "id", "openid email")
        val back = Credentials.fromJson(c.toJson())!!
        assertEquals(listOf("at", "Bearer", 123L, "rt", "id", "openid email"), listOf(back.accessToken, back.tokenType, back.expiresAtMillis, back.refreshToken, back.idToken, back.scope))
        assertNull(Credentials.fromJson("{}"))
        assertNull(Credentials.fromJson("[]"))
        assertTrue(Credentials("a", "Bearer", 1000, null, null, null).isExpired(0, 1000))
        assertFalse(Credentials("a", "Bearer", 70_000, null, null, null).isExpired(60, 1000))
    }

    @Test
    fun `a redirect nobody waits for any more still completes the sign-in`() = runBlocking<Unit> {
        val nine = fake.client()
        val url = CompletableDeferred<String>()
        val job = launch(Dispatchers.IO) {
            nine.signIn(BrowserStep { u, _ ->
                url.complete(u)
                CompletableDeferred<String>().await() // the browser stays open; the caller goes away
            })
        }
        val redirect = fake.authorize(url.await())
        job.cancelAndJoin()
        assertFalse(nine.isSignedIn)
        // What NineAuthActivity does when the redirect arrives and its coroutine is gone.
        AuthorizationBroker.deliver("gone", AuthorizationBroker.Result.Redirect(redirect))
        val state = withTimeout(5000) { nine.state.first { it is AuthState.SignedIn } }
        assertEquals("usr_alice", (state as AuthState.SignedIn).user.id)
    }

    @Test
    fun `a redirect that arrives before its client exists is kept for it`() = runBlocking<Unit> {
        val store = MemoryCredentialStore()
        val first = fake.client(store)
        val url = CompletableDeferred<String>()
        val job = launch(Dispatchers.IO) {
            first.signIn(BrowserStep { u, _ ->
                url.complete(u)
                CompletableDeferred<String>().await()
            })
        }
        val redirect = fake.authorize(url.await())
        job.cancelAndJoin()
        // The process dies while the browser is open; the redirect starts a new one.
        AuthorizationBroker.reset()
        AuthorizationBroker.deliver(null, AuthorizationBroker.Result.Redirect(redirect))
        val restarted = fake.client(store)
        val state = withTimeout(5000) { restarted.state.first { it is AuthState.SignedIn } }
        assertEquals("usr_alice", (state as AuthState.SignedIn).user.id)
    }

    @Test
    fun `redirects that belong to no sign-in are ignored`() = runBlocking<Unit> {
        val nine = fake.client()
        nine.state.first { it != AuthState.Loading }
        assertFalse(nine.offerRedirect("$REDIRECT?code=x&state=unknown"))
        assertFalse(nine.offerRedirect("$REDIRECT?code=x"))
        AuthorizationBroker.deliver(null, AuthorizationBroker.Result.Redirect("$REDIRECT?state=unknown"))
        assertFalse(nine.isSignedIn)
    }

    @Test
    fun `a custom transport sees every request`() = runBlocking<Unit> {
        val seen = mutableListOf<String>()
        val transport = HttpTransport { request -> seen.add("${request.method} ${request.url.substringBefore('?')}"); fake.execute(request) }
        val nine = NineClient(NineConfig(fake.issuer, fake.clientId, REDIRECT), MemoryCredentialStore(), transport)
        nine.signIn(fake.browser())
        assertEquals(listOf("GET ${fake.issuer}/.well-known/openid-configuration", "POST ${fake.issuer}/oauth/token", "GET ${fake.issuer}/.well-known/jwks.json"), seen)
        val failing = NineClient(NineConfig(fake.issuer, fake.clientId, REDIRECT), MemoryCredentialStore(), HttpTransport { throw IOException("offline") })
        expectNine(NineException.NETWORK_ERROR) { failing.signIn(fake.browser()) }
    }
}
