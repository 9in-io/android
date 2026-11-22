package io.ninein.android

import java.io.IOException
import java.net.URLDecoder
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

/**
 * An in-process 9in for tests: discovery, JWKS, the token endpoint (authorization code with PKCE,
 * refresh token rotation), revocation and userinfo, plus [authorize], which plays the hosted
 * sign-in page and returns the redirect. It checks what the real server checks (PKCE, redirect
 * URI, client) so the SDK can't pass by accident.
 */
internal class FakeNine(
    val issuer: String = "https://acme.9in.test",
    val clientId: String = "app_test",
    var key: TestKey = TestKey("RS256"),
) : HttpTransport {
    /** Extra keys published in the JWKS (rotation tests). */
    val extraKeys = mutableListOf<TestKey>()
    var publishKey = true
    var issParameterSupported = true
    var discoveryOverrides: Map<String, Any?> = emptyMap()
    var discoveryStatus = 200
    /** Changes the claims of every ID token issued from now on. */
    var idTokenClaims: (MutableMap<String, Any?>) -> Unit = {}
    var idTokenHeader: Map<String, Any?> = emptyMap()
    /** Replaces the ID token issued (a raw string), or null to issue a normal one. */
    var idTokenOverride: (() -> String?)? = null
    /** Changes token endpoint responses. */
    var tokenResponse: (MutableMap<String, Any?>) -> Unit = {}
    var accessTokenLifetime = 3600L
    var omitRefreshTokenOnRefresh = false
    var failNetwork = false
    /** Called on the token endpoint before answering a refresh (to hold concurrent requests). */
    var beforeRefresh: () -> Unit = {}
    var refreshError: String? = null

    val requests: MutableList<HttpRequest> = Collections.synchronizedList(mutableListOf())
    val discoveryCalls = AtomicInteger()
    val jwksCalls = AtomicInteger()
    val refreshCalls = AtomicInteger()
    val revoked: MutableList<Map<String, String>> = Collections.synchronizedList(mutableListOf())
    val authorizeRequests = mutableListOf<Map<String, String>>()

    var subject = "usr_alice"
    var email = "alice@acme.test"

    private class Code(val challenge: String, val redirectUri: String, val nonce: String?, val scope: String, val clientId: String)

    private val codes = HashMap<String, Code>()
    private val refreshTokens = HashMap<String, String>() // token -> subject
    private val usedRefreshTokens = HashSet<String>()
    private val accessTokens = HashSet<String>()

    val tokenEndpoint get() = "$issuer/oauth/token"

    // ---------------------------------------------------------------------------------------------
    // The hosted pages

    /** Plays the sign-in page: validates the authorization request and returns the redirect URL. */
    @Synchronized
    fun authorize(url: String, signedInAs: String = subject): String {
        val params = OidcClient.queryParams(url)
        authorizeRequests.add(params)
        check(url.startsWith("$issuer/oauth/authorize?")) { "unexpected authorization endpoint: $url" }
        check(params["client_id"] == clientId) { "client_id" }
        check(params["response_type"] == "code") { "response_type" }
        check(params["code_challenge_method"] == "S256") { "PKCE method" }
        check(Regex("^[A-Za-z0-9_-]{43,128}$").matches(params["code_challenge"] ?: "")) { "PKCE challenge" }
        subject = signedInAs
        val code = "code_" + Crypto.randomString(16)
        codes[code] = Code(params.getValue("code_challenge"), params.getValue("redirect_uri"), params["nonce"], params["scope"] ?: "openid", params.getValue("client_id"))
        val redirect = linkedMapOf("code" to code)
        params["state"]?.let { redirect["state"] = it }
        redirect["iss"] = issuer
        return withQuery(params.getValue("redirect_uri"), redirect)
    }

    /** A [BrowserStep] that signs in on [authorize]. */
    fun browser(transform: (String) -> String = { it }): BrowserStep = BrowserStep { url, _ -> transform(authorize(url)) }

    // ---------------------------------------------------------------------------------------------
    // HTTP

    override fun execute(request: HttpRequest): HttpResponse {
        if (failNetwork) throw IOException("connection refused")
        requests.add(request)
        val path = request.url.removePrefix(issuer).substringBefore('?')
        return when {
            request.method == "GET" && path == "/.well-known/openid-configuration" -> discovery()
            request.method == "GET" && path == "/.well-known/jwks.json" -> jwks()
            request.method == "POST" && path == "/oauth/token" -> token(form(request))
            request.method == "POST" && path == "/oauth/revoke" -> revoke(form(request))
            request.method == "GET" && path == "/oauth/userinfo" -> userinfo(request)
            else -> json(404, mapOf("error" to "not_found"))
        }
    }

    private fun discovery(): HttpResponse {
        discoveryCalls.incrementAndGet()
        if (discoveryStatus != 200) return json(discoveryStatus, mapOf("error" to "server_error"))
        val doc = linkedMapOf<String, Any?>(
            "issuer" to issuer,
            "authorization_endpoint" to "$issuer/oauth/authorize",
            "token_endpoint" to "$issuer/oauth/token",
            "userinfo_endpoint" to "$issuer/oauth/userinfo",
            "jwks_uri" to "$issuer/.well-known/jwks.json",
            "revocation_endpoint" to "$issuer/oauth/revoke",
            "end_session_endpoint" to "$issuer/oauth/logout",
            "code_challenge_methods_supported" to listOf("S256"),
            "authorization_response_iss_parameter_supported" to issParameterSupported,
        )
        doc.putAll(discoveryOverrides)
        return json(200, doc.filterValues { it != null })
    }

    @Synchronized
    private fun jwks(): HttpResponse {
        jwksCalls.incrementAndGet()
        val keys = (if (publishKey) listOf(key) else emptyList()) + extraKeys
        return json(200, mapOf("keys" to keys.map { it.jwk() }))
    }

    private fun token(form: Map<String, String>): HttpResponse {
        if (form["client_id"] != clientId) return json(401, mapOf("error" to "invalid_client"))
        return when (form["grant_type"]) {
            "authorization_code" -> synchronized(this) {
                val code = codes.remove(form["code"]) ?: return json(400, mapOf("error" to "invalid_grant", "error_description" to "invalid or expired code"))
                if (code.redirectUri != form["redirect_uri"]) return json(400, mapOf("error" to "invalid_grant", "error_description" to "redirect_uri mismatch"))
                val verifier = form["code_verifier"] ?: return json(400, mapOf("error" to "invalid_grant", "error_description" to "code_verifier required"))
                if (Pkce.challenge(verifier) != code.challenge) return json(400, mapOf("error" to "invalid_grant", "error_description" to "PKCE verification failed"))
                tokens(code.scope, code.nonce, withRefresh = "offline_access" in code.scope.split(" "))
            }
            "refresh_token" -> {
                refreshCalls.incrementAndGet()
                beforeRefresh()
                synchronized(this) {
                    refreshError?.let { return json(400, mapOf("error" to it)) }
                    val token = form["refresh_token"]
                    if (token == null || token in usedRefreshTokens || token !in refreshTokens) return json(400, mapOf("error" to "invalid_grant"))
                    usedRefreshTokens.add(token)
                    refreshTokens.remove(token)
                    tokens("openid profile email offline_access", nonce = null, withRefresh = !omitRefreshTokenOnRefresh)
                }
            }
            else -> json(400, mapOf("error" to "unsupported_grant_type"))
        }
    }

    private fun tokens(scope: String, nonce: String?, withRefresh: Boolean): HttpResponse {
        val access = "at_" + Crypto.randomString(16)
        accessTokens.add(access)
        val body = linkedMapOf<String, Any?>("access_token" to access, "token_type" to "Bearer", "expires_in" to accessTokenLifetime, "scope" to scope)
        if (withRefresh) {
            val refresh = "rt_" + Crypto.randomString(16)
            refreshTokens[refresh] = subject
            body["refresh_token"] = refresh
        }
        if ("openid" in scope.split(" ")) body["id_token"] = idTokenOverride?.invoke() ?: idToken(nonce)
        tokenResponse(body)
        return json(200, body.filterValues { it != null })
    }

    fun idToken(nonce: String?, signer: TestKey = key): String {
        val now = System.currentTimeMillis() / 1000
        val claims = linkedMapOf<String, Any?>(
            "iss" to issuer, "sub" to subject, "aud" to clientId, "azp" to clientId,
            "iat" to now, "exp" to now + 3600, "auth_time" to now, "sid" to "sid_1", "amr" to listOf("pwd"),
            "email" to email, "email_verified" to true, "name" to "Alice",
        )
        if (nonce != null) claims["nonce"] = nonce
        idTokenClaims(claims)
        return signer.jwt(claims.filterValues { it != null }, idTokenHeader)
    }

    @Synchronized
    private fun revoke(form: Map<String, String>): HttpResponse {
        revoked.add(form)
        form["token"]?.let {
            refreshTokens.remove(it)
            usedRefreshTokens.add(it)
            accessTokens.remove(it)
        }
        return HttpResponse(200)
    }

    @Synchronized
    private fun userinfo(request: HttpRequest): HttpResponse {
        val token = request.headers["Authorization"]?.removePrefix("Bearer ")
        if (token == null || token !in accessTokens) return json(401, mapOf("error" to "invalid_token"))
        return json(200, mapOf("sub" to subject, "email" to email, "email_verified" to true))
    }

    /** Makes a stored refresh token unusable (as if the session ended). */
    @Synchronized
    fun endSessions() {
        usedRefreshTokens.addAll(refreshTokens.keys)
        refreshTokens.clear()
        accessTokens.clear()
    }

    @Synchronized
    fun isRefreshTokenValid(token: String): Boolean = token in refreshTokens

    companion object {
        fun form(request: HttpRequest): Map<String, String> {
            val body = request.body?.toString(Charsets.UTF_8) ?: return emptyMap()
            return body.split('&').filter { it.isNotEmpty() }.associate {
                val (k, v) = it.split('=', limit = 2) + listOf("")
                URLDecoder.decode(k, "UTF-8") to URLDecoder.decode(v, "UTF-8")
            }
        }

        fun json(status: Int, body: Any?): HttpResponse =
            HttpResponse(status, mapOf("content-type" to listOf("application/json")), Json.stringify(body).toByteArray())
    }
}
