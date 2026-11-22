package io.ninein.android

import java.net.URI
import java.net.URISyntaxException

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
 * @param clockSkewSeconds how far the device clock may be off when the ID token's expiry is checked.
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
    /** The normalised issuer (validated, without a trailing slash). */
    public val issuer: String = Issuer.normalize(issuer, allowInsecureIssuer)

    init {
        if (clientId.isBlank()) throw NineException(NineException.INVALID_OPTIONS, "clientId is required")
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
    }

    public companion object {
        /** `openid profile email offline_access`. */
        @JvmField
        public val DEFAULT_SCOPES: List<String> = listOf("openid", "profile", "email", "offline_access")
    }
}

/** Issuer URL rules shared by every 9in SDK. */
internal object Issuer {
    /**
     * Validates an issuer and drops a trailing slash. Issuers must use https; plain http is
     * accepted only for localhost, `*.localhost` and loopback addresses, or with [allowInsecure].
     * Query strings, fragments and credentials are rejected.
     */
    fun normalize(issuer: String, allowInsecure: Boolean = false): String {
        val uri = try {
            URI(issuer.trim())
        } catch (e: URISyntaxException) {
            throw NineException(NineException.INVALID_ISSUER, "not a URL: $issuer", cause = e)
        }
        val scheme = uri.scheme?.lowercase()
        if (scheme == null || uri.host.isNullOrEmpty() || uri.isOpaque) throw NineException(NineException.INVALID_ISSUER, "not a URL: $issuer")
        if (uri.rawQuery != null || uri.rawFragment != null || uri.rawUserInfo != null) {
            throw NineException(NineException.INVALID_ISSUER, "an issuer has no query, fragment or credentials")
        }
        val secure = scheme == "https" || (scheme == "http" && (allowInsecure || isLocalHost(uri.host)))
        if (!secure) {
            throw NineException(
                NineException.INSECURE_ISSUER,
                "issuer must use https (got $scheme://${uri.host}); plain http is only accepted for localhost",
            )
        }
        return issuer.trim().removeSuffix("/")
    }

    /** Whether an endpoint from discovery may be used with this issuer (same security rule). */
    fun checkEndpoint(url: String, issuer: String, allowInsecure: Boolean, name: String): String {
        val uri = try {
            URI(url)
        } catch (e: URISyntaxException) {
            throw NineException(NineException.DISCOVERY_FAILED, "$name is not a URL", cause = e)
        }
        val scheme = uri.scheme?.lowercase()
        val issuerIsHttp = issuer.startsWith("http://", ignoreCase = true)
        val ok = !uri.host.isNullOrEmpty() && uri.rawFragment == null && uri.rawUserInfo == null &&
            (scheme == "https" || (scheme == "http" && (allowInsecure || issuerIsHttp) && (allowInsecure || isLocalHost(uri.host))))
        if (!ok) throw NineException(NineException.DISCOVERY_FAILED, "$name must be an https URL")
        return url
    }

    fun isLocalHost(hostname: String): Boolean {
        val host = hostname.lowercase().removePrefix("[").removeSuffix("]")
        return host == "localhost" || host.endsWith(".localhost") || host == "::1" ||
            Regex("^127(\\.\\d{1,3}){3}$").matches(host)
    }

    /** Issuers compare equal regardless of a trailing slash. */
    fun same(a: String?, b: String): Boolean = a != null && a.removeSuffix("/") == b.removeSuffix("/")
}
