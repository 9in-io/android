package io.ninein.android

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger

/**
 * Live end-to-end tests against 9in's production test tenant (`sdk-e2e`, sandbox environment, where
 * any password works), through the real hosted pages: the browser step is an HTTP client with a
 * cookie jar, the way `v2/e2e/lib/browser.ts` does it. Opt-in:
 *
 *   NINE_E2E=1 NINE_E2E_ENV=/path/to/.env.e2e ./gradlew :nine:testDebugUnitTest --tests '*LiveTest*'
 *
 * Settings come from the file named by NINE_E2E_ENV; `E2E_*` environment variables override them.
 * Test users are `android-<run>@sandbox.e2e.test`; they are deleted at the end through the
 * Management API with the confidential "E2E Server" client.
 */
class LiveTest {
    companion object {
        private val settings: Map<String, String> by lazy {
            val values = HashMap<String, String>()
            System.getenv("NINE_E2E_ENV")?.let { File(it) }?.takeIf { it.exists() }?.readLines()?.forEach { line ->
                Regex("^([A-Z0-9_]+)=(.*)$").find(line.trim())?.let { values[it.groupValues[1]] = it.groupValues[2] }
            }
            System.getenv().filterKeys { it.startsWith("E2E_") }.forEach { (k, v) -> values[k.removePrefix("E2E_")] = v }
            values
        }

        private fun env(name: String): String = settings[name]?.takeIf { it.isNotEmpty() } ?: error("E2E setting $name is missing")

        /** A marker per run, for the test users' emails. */
        private val RUN = java.lang.Long.toString(System.currentTimeMillis(), 36) + Crypto.randomString(3).lowercase().filter { it.isLetterOrDigit() }
        private val emails = mutableSetOf<String>()

        @JvmStatic
        @AfterClass
        fun deleteTestUsers() {
            if (System.getenv("NINE_E2E") != "1" || settings["SERVER_CLIENT_SECRET"].isNullOrEmpty() || emails.isEmpty()) return
            val token = clientCredentials(env("SANDBOX_ISSUER"), "management:users:read management:users:write")
            for (email in emails) {
                val found = http("GET", "${env("SANDBOX_ISSUER")}/api/v1/users/lookup?email=${java.net.URLEncoder.encode(email, "UTF-8")}", headers = mapOf("Authorization" to "Bearer $token"))
                if (found.status == 404) continue
                assertEquals("lookup $email", 200, found.status)
                @Suppress("UNCHECKED_CAST")
                val id = (Json.parseObject(found.text)["user"] as Map<String, Any?>)["id"] as String
                val deleted = http("DELETE", "${env("SANDBOX_ISSUER")}/api/v1/users/$id", headers = mapOf("Authorization" to "Bearer $token"))
                assertTrue("delete $email: HTTP ${deleted.status}", deleted.status == 204 || deleted.status == 200 || deleted.status == 404)
            }
        }

        private fun basic(): String {
            val raw = "${java.net.URLEncoder.encode(env("SERVER_CLIENT_ID"), "UTF-8")}:${java.net.URLEncoder.encode(env("SERVER_CLIENT_SECRET"), "UTF-8")}"
            return "Basic " + java.util.Base64.getEncoder().encodeToString(raw.toByteArray())
        }

        private fun clientCredentials(issuer: String, scope: String): String {
            val res = http("POST", "$issuer/oauth/token", mapOf("grant_type" to "client_credentials", "scope" to scope), mapOf("Authorization" to basic()))
            assertEquals("client credentials", 200, res.status)
            return Json.parseObject(res.text).string("access_token")!!
        }

        /** Introspects a token with the confidential client (null when its secret isn't configured). */
        private fun introspect(token: String): Boolean? {
            if (settings["SERVER_CLIENT_SECRET"].isNullOrEmpty()) return null
            val res = http("POST", "${env("SANDBOX_ISSUER")}/oauth/introspect", mapOf("token" to token), mapOf("Authorization" to basic()))
            assertEquals(200, res.status)
            return Json.parseObject(res.text)["active"] == true
        }

        private fun http(method: String, url: String, form: Map<String, String>? = null, headers: Map<String, String> = emptyMap()): HttpResponse =
            UrlConnectionTransport().execute(
                HttpRequest(
                    method,
                    url,
                    headers + (if (form != null) mapOf("Content-Type" to "application/x-www-form-urlencoded") else emptyMap()) + mapOf("Accept" to "application/json"),
                    form?.let { formEncode(it).toByteArray() },
                ),
            )
    }

    private val issuer get() = env("SANDBOX_ISSUER")
    private val clientId get() = env("SPA_CLIENT_ID")
    private val redirect get() = env("SPA_REDIRECT_URI")
    private val email get() = "android-$RUN@sandbox.e2e.test".also { emails.add(it) }

    @Before
    fun enabled() {
        assumeTrue("live tests are opt-in: NINE_E2E=1", System.getenv("NINE_E2E") == "1")
        AuthorizationBroker.reset()
    }

    /** An HTTP client with a cookie jar per host and manual redirects: enough to drive the hosted pages. */
    private class HostedBrowser {
        private val cookies = HashMap<String, LinkedHashMap<String, String>>()

        class Page(val url: String, val status: Int, val location: String?, val html: String)

        fun request(url: String, form: Map<String, String>? = null): Page {
            val target = URL(url)
            val connection = target.openConnection() as HttpURLConnection
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.setRequestProperty("User-Agent", "9in-e2e/1.0")
            cookies[target.host]?.takeIf { it.isNotEmpty() }?.let { jar -> connection.setRequestProperty("Cookie", jar.entries.joinToString("; ") { "${it.key}=${it.value}" }) }
            if (form != null) {
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                connection.setRequestProperty("Origin", "${target.protocol}://${target.authority}")
                connection.setRequestProperty("Referer", url)
                connection.outputStream.use { it.write(formEncode(form).toByteArray()) }
            }
            val status = connection.responseCode
            val jar = cookies.getOrPut(target.host) { LinkedHashMap() }
            for ((name, values) in connection.headerFields) {
                if (name == null || !name.equals("Set-Cookie", ignoreCase = true)) continue
                for (header in values) {
                    val parts = header.split(';')
                    val pair = parts[0]
                    val eq = pair.indexOf('=')
                    if (eq <= 0) continue
                    val key = pair.substring(0, eq).trim()
                    val value = pair.substring(eq + 1).trim()
                    val expired = parts.drop(1).any { it.trim().equals("max-age=0", ignoreCase = true) }
                    if (expired || value.isEmpty()) jar.remove(key) else jar[key] = value
                }
            }
            val body = (if (status >= 400) connection.errorStream else connection.inputStream)?.use { it.readBytes().toString(Charsets.UTF_8) } ?: ""
            return Page(url, status, connection.getHeaderField("Location")?.let { URI(url).resolve(it).toString() }, body)
        }

        /** Follows redirects until one starts with [stopAt] (returned as a URL) or a page is reached. */
        fun follow(start: String, stopAt: String): Pair<String?, Page?> {
            var url = start
            repeat(20) {
                if (url.startsWith(stopAt)) return url to null
                val page = request(url)
                if (page.status in 300..399 && page.location != null) url = page.location else return null to page
            }
            error("too many redirects")
        }

        fun hiddenFields(html: String): Map<String, String> {
            val form = html.split("<form").getOrNull(1)?.substringBefore("</form>") ?: ""
            return Regex("<input\\b[^>]*>").findAll(form).map { it.value }.filter { it.contains("type=\"hidden\"") }.mapNotNull { input ->
                val name = Regex("name=\"([^\"]+)\"").find(input)?.groupValues?.get(1) ?: return@mapNotNull null
                val value = Regex("value=\"([^\"]*)\"").find(input)?.groupValues?.get(1) ?: ""
                name to value.replace("&amp;", "&").replace("&quot;", "\"").replace("&#x27;", "'").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">")
            }.toMap()
        }

        fun formAction(html: String, pageUrl: String): String {
            val form = html.split("<form").getOrNull(1) ?: ""
            val action = Regex("action=\"([^\"]*)\"").find(form)?.groupValues?.get(1)?.replace("&amp;", "&") ?: ""
            return URI(pageUrl).resolve(action.ifEmpty { pageUrl }).toString()
        }

        /** Signs in on the hosted page with an identifier and password; returns the callback URL. */
        fun signIn(authorizeUrl: String, redirectUri: String, identifier: String, password: String): String {
            val (callback, page) = follow(authorizeUrl, redirectUri)
            if (callback != null) return callback // single sign-on: no page at all
            check(page!!.html.contains("name=\"identifier\"")) { "no sign-in form at ${page.url} (HTTP ${page.status})" }
            val submitted = request(formAction(page.html, page.url), hiddenFields(page.html) + mapOf("identifier" to identifier, "password" to password, "action" to "password"))
            val location = submitted.location ?: error("sign-in did not redirect (HTTP ${submitted.status})")
            val (done, last) = follow(location, redirectUri)
            return done ?: error("sign-in stopped at ${last!!.url} (HTTP ${last.status})")
        }
    }

    /** The browser step of a test: the hosted pages through [HostedBrowser], as [email]. */
    private fun step(browser: HostedBrowser, user: String, seen: MutableList<String>? = null) = BrowserStep { url, redirectUri ->
        seen?.add(url)
        browser.signIn(url, redirectUri, user, "any-password-works-in-sandbox").also { seen?.add(it) }
    }

    private val tokenRequests = AtomicInteger()
    private val counting = HttpTransport { request ->
        if (request.url.endsWith("/oauth/token") && FakeNine.form(request)["grant_type"] == "refresh_token") tokenRequests.incrementAndGet()
        UrlConnectionTransport().execute(request)
    }

    private fun client(clock: Clock = Clock.SYSTEM, audience: String? = null, scopes: List<String> = NineConfig.DEFAULT_SCOPES) =
        NineClient(NineConfig(issuer, clientId, redirect, scopes, audience), MemoryCredentialStore(), counting, Dispatchers.IO, clock)

    @Test
    fun `discovery advertises what the SDK relies on`() = runBlocking<Unit> {
        val discovery = client().oidc.discovery()
        assertEquals(issuer, discovery.issuer)
        assertTrue(discovery.authorizationResponseIssParameterSupported)
        assertEquals("$issuer/oauth/token", discovery.tokenEndpoint)
        assertNotNull(discovery.revocationEndpoint)
        assertNotNull(discovery.endSessionEndpoint)
        @Suppress("UNCHECKED_CAST")
        assertTrue((discovery.raw["code_challenge_methods_supported"] as List<String>).contains("S256"))
    }

    @Test
    fun `signs in through the hosted pages with PKCE, state, nonce and a verified ID token`() = runBlocking<Unit> {
        val nine = client()
        val seen = mutableListOf<String>()
        val user = nine.signIn(step(HostedBrowser(), email, seen))
        assertEquals(email, user.email)
        assertTrue(user.id.isNotEmpty())
        assertEquals(issuer, user["iss"])
        val callback = seen.last()
        assertEquals(issuer, OidcClient.queryParams(callback)["iss"])
        assertEquals(OidcClient.queryParams(seen.first())["state"], OidcClient.queryParams(callback)["state"])
        val credentials = nine.credentials()!!
        assertNotNull(credentials.refreshToken)
        assertTrue(credentials.scopes.containsAll(listOf("openid", "offline_access")))
        // The ID token's signature was checked against the tenant's JWKS (its kid and algorithm).
        val header = Jwt.decode(credentials.idToken!!).header
        assertTrue(Jws.isSupported(header["alg"] as String))
        val info = nine.userInfo()
        assertEquals(user.id, info["sub"])
        assertEquals(email, info["email"])
    }

    @Test
    fun `gets access tokens for an API`() = runBlocking<Unit> {
        val audience = env("API_AUDIENCE")
        val nine = client(audience = audience, scopes = NineConfig.DEFAULT_SCOPES + "read:things")
        nine.signIn(step(HostedBrowser(), email))
        val token = nine.accessToken()
        val jwt = Jwt.decode(token)
        assertEquals("at+jwt", (jwt.header["typ"] as String).lowercase())
        val aud = jwt.payload["aud"]
        assertTrue(aud == audience || (aud is List<*> && audience in aud))
        assertEquals(clientId, jwt.payload["client_id"])
        assertTrue((jwt.payload["scope"] as String).split(" ").contains("read:things"))
        introspect(token)?.let { assertTrue("introspection says the token is live", it) }
    }

    @Test
    fun `refreshes with rotation once for concurrent callers`() = runBlocking<Unit> {
        val clock = TestClock()
        val nine = client(clock = clock)
        nine.signIn(step(HostedBrowser(), email))
        val before = nine.credentials()!!
        clock.advance(3600) // the access token is now expired as far as the SDK knows
        val tokens = (1..10).map { async(Dispatchers.IO) { nine.accessToken() } }.awaitAll()
        assertEquals(1, tokens.toSet().size)
        assertEquals(1, tokenRequests.get())
        val after = nine.credentials()!!
        assertNotEquals(before.accessToken, after.accessToken)
        assertNotEquals("the refresh token rotated", before.refreshToken, after.refreshToken)
        assertEquals(before.idToken?.let { Jwt.decode(it).payload["sub"] }, nine.user!!.id)
        // Within 30 s, the old refresh token is a race, not reuse: 9in answers with the newest one.
        val repeat = http("POST", "$issuer/oauth/token", mapOf("grant_type" to "refresh_token", "refresh_token" to before.refreshToken!!, "client_id" to clientId))
        assertEquals(200, repeat.status)
        assertEquals(after.refreshToken, Json.parseObject(repeat.text).string("refresh_token"))
        // And the SDK keeps working with the newest one.
        assertNotNull(nine.refresh().refreshToken)
    }

    @Test
    fun `single sign-on, then sign-out revokes the refresh token and ends the 9in session`() = runBlocking<Unit> {
        val browser = HostedBrowser()
        val nine = client()
        nine.signIn(step(browser, email))
        // The 9in session in the browser signs the next sign-in in without a page.
        val second = client()
        var sawPage = false
        second.signIn(BrowserStep { url, redirectUri ->
            val (callback, page) = browser.follow(url, redirectUri)
            sawPage = page != null
            callback ?: error("expected single sign-on")
        })
        assertFalse(sawPage)

        val credentials = nine.credentials()!!
        val returnTo = URI(redirect).resolve("/").toString()
        var logoutUrl: String? = null
        nine.signOut(BrowserStep { url, redirectUri ->
            logoutUrl = url
            val (back, page) = browser.follow(url, redirectUri)
            back ?: error("logout stopped at ${page!!.url} (HTTP ${page.status})")
        }, postLogoutRedirectUri = returnTo)
        assertFalse(nine.isSignedIn)
        assertNull(nine.credentials())
        val p = OidcClient.queryParams(logoutUrl!!)
        assertTrue(logoutUrl!!.startsWith("$issuer/oauth/logout?"))
        assertEquals(credentials.idToken, p["id_token_hint"])
        // The refresh token is revoked…
        val refused = http("POST", "$issuer/oauth/token", mapOf("grant_type" to "refresh_token", "refresh_token" to credentials.refreshToken!!, "client_id" to clientId))
        assertEquals(400, refused.status)
        assertEquals("invalid_grant", Json.parseObject(refused.text).string("error"))
        expectNine(NineException.LOGIN_REQUIRED) { nine.accessToken() }
        // …and the 9in session is over: the next sign-in shows the sign-in page again.
        val third = client()
        val shown = third.oidc.authorizationRequest(SignInOptions(), signUp = false).url
        val (callback, page) = browser.follow(shown, redirect)
        assertNull(callback)
        assertTrue(page!!.html.contains("name=\"identifier\""))
        // The second app's refresh token belonged to the ended session too.
        expectNine(NineException.LOGIN_REQUIRED) { second.refresh() }
    }

    @Test
    fun `opens the sign-up page`() = runBlocking<Unit> {
        val nine = client()
        var page: HostedBrowser.Page? = null
        expectNine(NineException.CANCELED) {
            nine.signUp(BrowserStep { url, redirectUri ->
                assertEquals("create", OidcClient.queryParams(url)["prompt"])
                page = HostedBrowser().follow(url, redirectUri).second
                throw NineException(NineException.CANCELED)
            }, SignInOptions(loginHint = "new@sandbox.e2e.test", locale = "de"))
        }
        assertEquals(200, page!!.status)
        assertTrue(page!!.url, Regex("/register|/signup").containsMatchIn(page!!.url))
    }

    @Test
    fun `refuses forged redirects`() = runBlocking<Unit> {
        expectNine(NineException.INVALID_STATE) {
            client().signIn(BrowserStep { url, r -> HostedBrowser().signIn(url, r, email, "x").replace(Regex("state=[^&]+"), "state=forged") })
        }
        expectNine(NineException.INVALID_ISSUER) {
            client().signIn(BrowserStep { url, r -> HostedBrowser().signIn(url, r, email, "x").replace(Regex("iss=[^&]+"), "iss=https%3A%2F%2Fevil.example") })
        }
        expectNine(NineException.INVALID_GRANT) {
            client().signIn(BrowserStep { url, r -> HostedBrowser().signIn(url, r, email, "x").replace(Regex("code=[^&]+"), "code=not-the-code") })
        }
        // A real error redirect from 9in: an unknown audience.
        expectNine("invalid_target") {
            client(audience = "https://unknown.e2e.9in.test").signIn(BrowserStep { url, r -> HostedBrowser().follow(url, r).first ?: error("no redirect") })
        }
    }
}
