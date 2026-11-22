package io.ninein.android

/**
 * Every failure of the SDK. [code] is a stable, machine-readable reason: an OAuth error from 9in
 * (`access_denied`, `invalid_grant`, …) or one of the SDK's own codes listed in the companion.
 * [status] is the HTTP status when the error came from an HTTP response.
 */
public class NineException(
    public val code: String,
    public val description: String? = null,
    public val status: Int? = null,
    cause: Throwable? = null,
) : Exception(if (description.isNullOrEmpty()) code else "$code: $description", cause) {

    public companion object {
        /** Nobody is signed in, or the session ended (the refresh token was revoked or expired): sign in again. */
        public const val LOGIN_REQUIRED: String = "login_required"

        /** The user closed the browser before finishing. */
        public const val CANCELED: String = "canceled"

        /** The redirect did not belong to the sign-in in progress (wrong, missing or replayed `state`). */
        public const val INVALID_STATE: String = "invalid_state"

        /** The redirect named another issuer (RFC 9207 `iss`), or discovery answered for another issuer. */
        public const val INVALID_ISSUER: String = "invalid_issuer"

        /** The issuer is not https (plain http is only accepted for localhost and loopback addresses). */
        public const val INSECURE_ISSUER: String = "insecure_issuer"

        /** The ID token failed a check: signature, issuer, audience, expiry, nonce or subject. */
        public const val INVALID_ID_TOKEN: String = "invalid_id_token"

        /** The redirect had neither a code nor an error. */
        public const val MISSING_CODE: String = "missing_code"

        /** The access token was refused (userinfo answered 401). */
        public const val INVALID_TOKEN: String = "invalid_token"

        /** The refresh token is no longer valid (also the cause of [LOGIN_REQUIRED] after a refresh). */
        public const val INVALID_GRANT: String = "invalid_grant"

        /** The user declined, or 9in refused the request. */
        public const val ACCESS_DENIED: String = "access_denied"

        /** Wrong constructor arguments (empty client ID, malformed redirect URI, …). */
        public const val INVALID_OPTIONS: String = "invalid_options"

        /** 9in could not be reached (no network, DNS, TLS or timeout). */
        public const val NETWORK_ERROR: String = "network_error"

        /** 9in answered with something that is not the expected JSON. */
        public const val INVALID_RESPONSE: String = "invalid_response"

        /** The discovery document could not be fetched or is incomplete. */
        public const val DISCOVERY_FAILED: String = "discovery_failed"

        /** The signing keys (JWKS) could not be fetched. */
        public const val JWKS_UNAVAILABLE: String = "jwks_unavailable"

        /** The userinfo endpoint answered with an error other than 401. */
        public const val USERINFO_FAILED: String = "userinfo_failed"

        /** The [CredentialStore] failed to save (for example, the Android Keystore is unavailable). */
        public const val STORAGE_ERROR: String = "storage_error"

        /** No browser is installed that can show the sign-in page. */
        public const val BROWSER_NOT_FOUND: String = "browser_not_found"
    }
}
