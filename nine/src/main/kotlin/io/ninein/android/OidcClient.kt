package io.ninein.android

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.URLDecoder

/** Milliseconds since the epoch; replaced in tests. */
internal fun interface Clock {
    fun nowMillis(): Long

    companion object {
        val SYSTEM = Clock { System.currentTimeMillis() }
    }
}

/** Options for one sign-in. */
public class SignInOptions @JvmOverloads constructor(
    /** `login` (sign in again), `consent`, `select_account` or `none` (fail instead of showing a page). */
    public val prompt: String? = null,
    /** Prefills the identifier on the sign-in page. */
    public val loginHint: String? = null,
    /** Ask the user to sign in again if their last sign-in is older than this. */
    public val maxAgeSeconds: Long? = null,
    /** Language of the hosted pages for this sign-in (`ui_locales`); overrides [NineConfig.locale]. */
    public val locale: String? = null,
    /** Extra authorization parameters. They never replace the ones the SDK sets (state, nonce, PKCE, …). */
    public val extraParams: Map<String, String> = emptyMap(),
)

internal class AuthorizationRequest(val url: String, val pending: PendingLogin)

/** Tokens from the token endpoint, with the verified claims of the ID token that came with them. */
internal class TokenResult(val credentials: Credentials, val claims: Map<String, Any?>?)

/**
 * The OpenID Connect protocol for a public client, in plain Kotlin: discovery, the authorization
 * request with PKCE, the callback checks, the code exchange, refresh with rotation, ID token
 * verification against the JWKS, revocation, userinfo and the end-session URL.
 */
internal class OidcClient(
    val config: NineConfig,
    private val http: HttpTransport,
    private val io: CoroutineDispatcher,
    private val clock: Clock = Clock.SYSTEM,
) {
    private val discoveryLock = Mutex()
    private var discovery: Discovery? = null
    private var discoveryFetchedAt = 0L

    private val jwksLock = Mutex()
    private var jwks: List<Map<String, Any?>>? = null
    private var jwksFetchedAt = 0L
    private val missingKids = HashMap<String, Long>()

    // -------------------------------------------------------------------------------------------
    // HTTP

    private suspend fun send(request: HttpRequest): HttpResponse = withContext(io) {
        try {
            http.execute(request)
        } catch (e: IOException) {
            throw NineException(NineException.NETWORK_ERROR, e.message ?: e.javaClass.simpleName, cause = e)
        }
    }

    private suspend fun getJson(url: String, headers: Map<String, String> = emptyMap(), failure: String): Map<String, Any?> {
        val response = send(HttpRequest("GET", url, mapOf("Accept" to "application/json") + headers))
        if (response.status != 200) throw NineException(failure, "HTTP ${response.status}", response.status)
        return Json.parseObject(response.text)
    }

    /** POSTs a form to a 9in endpoint; errors become [NineException] with the OAuth error code. */
    private suspend fun postForm(url: String, form: Map<String, String>): Map<String, Any?> {
        val response = send(
            HttpRequest(
                "POST",
                url,
                mapOf("Content-Type" to "application/x-www-form-urlencoded", "Accept" to "application/json"),
                formEncode(form).toByteArray(Charsets.UTF_8),
            ),
        )
        if (response.status !in 200..299) {
            val json = try {
                Json.parseObject(response.text)
            } catch (e: NineException) {
                emptyMap()
            }
            throw NineException(json.string("error") ?: "request_failed", json.string("error_description") ?: "HTTP ${response.status}", response.status)
        }
        if (response.body.isEmpty()) return emptyMap()
        return Json.parseObject(response.text)
    }

    // -------------------------------------------------------------------------------------------
    // Discovery and keys

    suspend fun discovery(): Discovery = discoveryLock.withLock {
        val cached = discovery
        if (cached != null && clock.nowMillis() - discoveryFetchedAt < DISCOVERY_TTL) return cached
        val json = getJson("${config.issuer}/.well-known/openid-configuration", failure = NineException.DISCOVERY_FAILED)
        Discovery.parse(json, config.issuer, config.allowInsecureIssuer).also {
            discovery = it
            discoveryFetchedAt = clock.nowMillis()
        }
    }

    private suspend fun keys(force: Boolean): List<Map<String, Any?>> {
        val cached = jwks
        if (cached != null && !force && clock.nowMillis() - jwksFetchedAt < JWKS_TTL) return cached
        val json = getJson(discovery().jwksUri, failure = NineException.JWKS_UNAVAILABLE)
        val keys = (json["keys"] as? List<*>)?.filterIsInstance<Map<*, *>>()?.map { key ->
            key.entries.associate { it.key.toString() to it.value }
        } ?: throw NineException(NineException.JWKS_UNAVAILABLE, "the JWKS has no keys")
        jwks = keys
        jwksFetchedAt = clock.nowMillis()
        return keys
    }

    /**
     * The JWK for a token's `kid`. An unknown kid (a key rotation) refetches the JWKS once; a kid
     * still unknown after that is not looked up again for a minute.
     */
    internal suspend fun findKey(kid: String?, alg: String): Map<String, Any?>? = jwksLock.withLock {
        fun pick(keys: List<Map<String, Any?>>): Map<String, Any?>? =
            if (kid != null) keys.firstOrNull { it["kid"] == kid } else keys.filter { Jws.keyFits(it, alg) }.singleOrNull()

        pick(keys(force = false))?.let { return it }
        val missKey = kid ?: "<none>:$alg"
        val missedAt = missingKids[missKey]
        if (missedAt != null && clock.nowMillis() - missedAt < UNKNOWN_KID_THROTTLE) return null
        val refreshed = pick(keys(force = true))
        if (refreshed == null) {
            if (missingKids.size > 100) missingKids.clear()
            missingKids[missKey] = clock.nowMillis()
        }
        refreshed
    }

    // -------------------------------------------------------------------------------------------
    // Sign-in

    suspend fun authorizationRequest(options: SignInOptions, signUp: Boolean): AuthorizationRequest {
        val endpoint = discovery().authorizationEndpoint
        val pending = PendingLogin(
            state = Crypto.randomString(24),
            nonce = Crypto.randomString(24),
            verifier = Pkce.verifier(),
            redirectUri = config.redirectUri,
            createdAtMillis = clock.nowMillis(),
        )
        val params = LinkedHashMap<String, String>()
        for ((key, value) in options.extraParams) if (key !in RESERVED) params[key] = value
        params["response_type"] = "code"
        params["client_id"] = config.clientId
        params["redirect_uri"] = config.redirectUri
        params["scope"] = config.scopes.joinToString(" ")
        params["state"] = pending.state
        params["nonce"] = pending.nonce
        params["code_challenge"] = Pkce.challenge(pending.verifier)
        params["code_challenge_method"] = "S256"
        config.audience?.let { params["audience"] = it }
        (if (signUp) "create" else options.prompt)?.let { params["prompt"] = it }
        options.loginHint?.let { params["login_hint"] = it }
        options.maxAgeSeconds?.let { params["max_age"] = it.toString() }
        (options.locale ?: config.locale)?.let { params["ui_locales"] = it }
        return AuthorizationRequest(withQuery(endpoint, params), pending)
    }

    /**
     * Checks the redirect from 9in against the pending sign-in (state, issuer, error), exchanges
     * the code with the PKCE verifier and verifies the ID token. Nothing is stored here.
     */
    suspend fun exchangeCode(callbackUrl: String, pending: PendingLogin?): TokenResult {
        val params = queryParams(callbackUrl)
        if (pending == null) throw NineException(NineException.INVALID_STATE, "no sign-in in progress")
        if (clock.nowMillis() - pending.createdAtMillis > PENDING_TTL) {
            throw NineException(NineException.INVALID_STATE, "the sign-in took too long; start again")
        }
        val state = params["state"]
        if (state == null || !Crypto.safeEquals(state, pending.state)) throw NineException(NineException.INVALID_STATE, "state mismatch")
        val discovery = discovery()
        // RFC 9207: the issuer says who answered; when it advertises that, the parameter is required.
        val iss = params["iss"]
        if (iss != null && !Issuer.same(iss, config.issuer)) throw NineException(NineException.INVALID_ISSUER, "unexpected issuer $iss")
        if (iss == null && discovery.authorizationResponseIssParameterSupported) {
            throw NineException(NineException.INVALID_ISSUER, "the redirect has no iss parameter")
        }
        params["error"]?.let { throw NineException(it, params["error_description"]) }
        val code = params["code"]?.takeIf { it.isNotEmpty() } ?: throw NineException(NineException.MISSING_CODE, "no authorization code in the redirect")

        val json = postForm(
            discovery.tokenEndpoint,
            mapOf(
                "grant_type" to "authorization_code",
                "code" to code,
                "redirect_uri" to pending.redirectUri,
                "client_id" to config.clientId,
                "code_verifier" to pending.verifier,
            ),
        )
        val credentials = Credentials.fromTokenResponse(json, clock.nowMillis())
        val idToken = json.string("id_token")
        val claims = when {
            idToken != null -> verifyIdToken(idToken, nonce = pending.nonce)
            "openid" in config.scopes -> throw NineException(NineException.INVALID_ID_TOKEN, "no ID token in the token response")
            else -> null
        }
        return TokenResult(credentials, claims)
    }

    /**
     * New tokens from the refresh token. 9in rotates it: the new one is kept (the old one only if
     * none came back). A new ID token must be for the same user.
     */
    suspend fun refresh(current: Credentials, currentSubject: String?): TokenResult {
        val refreshToken = current.refreshToken ?: throw NineException(NineException.LOGIN_REQUIRED, "no refresh token")
        val json = postForm(
            discovery().tokenEndpoint,
            mapOf("grant_type" to "refresh_token", "refresh_token" to refreshToken, "client_id" to config.clientId),
        )
        val credentials = Credentials.fromTokenResponse(json, clock.nowMillis(), previous = current)
        val claims = json.string("id_token")?.let { verifyIdToken(it, nonce = null, expectedSubject = currentSubject) }
        return TokenResult(credentials, claims)
    }

    suspend fun revoke(token: String, hint: String) {
        val endpoint = discovery().revocationEndpoint ?: return
        postForm(endpoint, mapOf("token" to token, "token_type_hint" to hint, "client_id" to config.clientId))
    }

    suspend fun userInfo(accessToken: String): Map<String, Any?> {
        val endpoint = discovery().userinfoEndpoint ?: "${config.issuer}/oauth/userinfo"
        val response = send(HttpRequest("GET", endpoint, mapOf("Authorization" to "Bearer $accessToken", "Accept" to "application/json")))
        if (response.status == 401) throw NineException(NineException.INVALID_TOKEN, "HTTP 401", 401)
        if (response.status != 200) throw NineException(NineException.USERINFO_FAILED, "HTTP ${response.status}", response.status)
        return Json.parseObject(response.text)
    }

    suspend fun endSessionUrl(idTokenHint: String?, postLogoutRedirectUri: String?, state: String?): String {
        val endpoint = discovery().endSessionEndpoint ?: "${config.issuer}/oauth/logout"
        val params = LinkedHashMap<String, String>()
        params["client_id"] = config.clientId
        idTokenHint?.let { params["id_token_hint"] = it }
        postLogoutRedirectUri?.let { params["post_logout_redirect_uri"] = it }
        state?.let { params["state"] = it }
        return withQuery(endpoint, params)
    }

    // -------------------------------------------------------------------------------------------
    // ID tokens

    /**
     * Verifies an ID token: signature against the tenant's JWKS (the key decides the algorithm),
     * issuer, audience (`azp` when there are several), expiry, `nbf`, subject and nonce.
     */
    suspend fun verifyIdToken(idToken: String, nonce: String?, expectedSubject: String? = null): Map<String, Any?> {
        fun fail(message: String): Nothing = throw NineException(NineException.INVALID_ID_TOKEN, message)
        val jwt = try {
            Jwt.decode(idToken)
        } catch (e: IllegalArgumentException) {
            fail("malformed ID token")
        }
        val typ = (jwt.header["typ"] as? String)?.lowercase()
        if (typ == "at+jwt" || typ == "application/at+jwt") fail("not an ID token")
        val alg = jwt.header["alg"] as? String ?: fail("no algorithm")
        if (Jws.isHmac(alg)) fail("$alg ID tokens can't be verified by an app; give the tenant an asymmetric default key")
        if (!Jws.isSupported(alg)) fail("unsupported algorithm $alg")
        val jwk = findKey(jwt.header["kid"] as? String, alg) ?: fail("unknown signing key")
        if (!Jws.keyFits(jwk, alg)) fail("algorithm does not match the key")
        if (!Jws.verify(alg, jwk, jwt.signingInput, jwt.signature)) fail("bad signature")

        val claims = jwt.payload
        val now = clock.nowMillis() / 1000
        val skew = config.clockSkewSeconds
        if (!Issuer.same(claims["iss"] as? String, config.issuer)) fail("issuer mismatch")
        val audience = when (val aud = claims["aud"]) {
            is String -> listOf(aud)
            is List<*> -> aud.filterIsInstance<String>()
            else -> emptyList()
        }
        if (config.clientId !in audience) fail("audience mismatch")
        val azp = claims["azp"] as? String
        if ((audience.size > 1 || azp != null) && azp != config.clientId) fail("authorized party mismatch")
        val exp = claims.long("exp") ?: fail("no expiry")
        if (exp + skew < now) fail("ID token expired")
        val nbf = claims.long("nbf")
        if (nbf != null && nbf - skew > now) fail("ID token not yet valid")
        val sub = claims["sub"] as? String
        if (sub.isNullOrEmpty()) fail("missing subject")
        if (expectedSubject != null && sub != expectedSubject) fail("the ID token is for another user")
        if (nonce != null) {
            val got = claims["nonce"] as? String
            if (got == null || !Crypto.safeEquals(got, nonce)) fail("nonce mismatch")
        }
        return claims
    }

    internal companion object {
        const val DISCOVERY_TTL = 60 * 60_000L
        const val JWKS_TTL = 10 * 60_000L
        const val UNKNOWN_KID_THROTTLE = 60_000L
        const val PENDING_TTL = 15 * 60_000L
        val RESERVED = setOf("response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method")

        /** Query parameters of a redirect URL (decoded; the first value wins). */
        fun queryParams(url: String): Map<String, String> {
            val query = url.substringBefore('#').substringAfter('?', "")
            val params = LinkedHashMap<String, String>()
            for (pair in query.split('&')) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                try {
                    val name = URLDecoder.decode(if (eq >= 0) pair.substring(0, eq) else pair, "UTF-8")
                    val value = if (eq >= 0) URLDecoder.decode(pair.substring(eq + 1), "UTF-8") else ""
                    if (name !in params) params[name] = value
                } catch (e: IllegalArgumentException) {
                    // A malformed escape: ignore the pair (the checks then fail on what is missing).
                }
            }
            return params
        }
    }
}
