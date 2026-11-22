package io.ninein.android

import io.ninein.AuthClient
import io.ninein.LoginOptions
import io.ninein.http.HttpTransport
import java.net.URI
import java.net.URISyntaxException
import java.time.Clock
import java.time.Duration

/**
 * What [NineClient] needs to know about your application.
 *
 * @param issuer your tenant's issuer, e.g. `https://acme.9in.io` or your custom domain. Must be
 *   https (plain http is only accepted for localhost and loopback addresses, or with
 *   [allowInsecureIssuer]). A trailing slash is dropped.
 * @param clientId the application's client ID (a **Native / Mobile** application in the console).
 * @param redirectUri the callback URL registered on the application: a private-use scheme such as
 *   `com.acme.app:/callback` (set `nineRedirectScheme` to `com.acme.app`), or an https App Link.
 * @param scopes `openid` gives an ID token (the user's claims), `offline_access` a refresh token.
 * @param audience an API identifier, to get access tokens for that API.
 * @param locale language of the hosted pages (`ui_locales`), e.g. `"de"`.
 * @param allowInsecureIssuer accept a plain-http issuer other than localhost (development only).
 * @param clockSkewSeconds how far the device clock may be off when the ID token's times are checked.
 */
public class NineConfig @JvmOverloads constructor(
    issuer: String,
    public val clientId: String,
    public val redirectUri: String,
    public val scopes: List<String> = DEFAULT_SCOPES,
    public val audience: String? = null,
    public val locale: String? = null,
    public val allowInsecureIssuer: Boolean = false,
    public val clockSkewSeconds: Long = 300,
) {
    private val rawIssuer: String = issuer

    /** The normalised issuer (validated, without a trailing slash). */
    public val issuer: String

    init {
        if (redirectUri.isBlank()) throw NineException(NineException.INVALID_OPTIONS, "redirectUri is required")
        val parsed = try {
            URI(redirectUri)
        } catch (e: URISyntaxException) {
            throw NineException(NineException.INVALID_OPTIONS, "redirectUri is not a URI", cause = e)
        }
        if (parsed.scheme.isNullOrEmpty() || parsed.rawFragment != null) {
            throw NineException(NineException.INVALID_OPTIONS, "redirectUri needs a scheme and no fragment, e.g. com.acme.app:/callback")
        }
        if (scopes.any { it.isBlank() || it.contains(' ') }) throw NineException(NineException.INVALID_OPTIONS, "scopes must be single words")
        if (clockSkewSeconds < 0) throw NineException(NineException.INVALID_OPTIONS, "clockSkewSeconds must not be negative")
        // The Java core validates the issuer (https, no query/fragment/credentials) and the client ID.
        this.issuer = core { authClient(null, null).issuer() }
    }

    /** The Java SDK's [AuthClient] for this configuration: the protocol under [NineClient]. */
    internal fun authClient(transport: HttpTransport?, clock: Clock?): AuthClient {
        val builder = AuthClient.builder()
            .issuer(rawIssuer)
            .clientId(clientId)
            .redirectUri(redirectUri)
            .scopes(*scopes.toTypedArray())
            .audience(audience)
            .allowInsecureIssuer(allowInsecureIssuer)
            .leeway(Duration.ofSeconds(clockSkewSeconds))
        if (transport != null) builder.transport(transport)
        if (clock != null) builder.clock(clock)
        return builder.build()
    }

    public companion object {
        /** `openid profile email offline_access`. */
        @JvmField
        public val DEFAULT_SCOPES: List<String> = listOf("openid", "profile", "email", "offline_access")
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
) {
    internal fun toLoginOptions(config: NineConfig, signUp: Boolean): LoginOptions {
        val builder = LoginOptions.builder().extra(extraParams)
        if (signUp) builder.screen("signup") else prompt?.let { builder.prompt(it) }
        loginHint?.let { builder.loginHint(it) }
        maxAgeSeconds?.let { builder.extra("max_age", it.toString()) }
        (locale ?: config.locale)?.let { builder.locale(it) }
        return builder.build()
    }
}
