package io.ninein.android

import io.ninein.TokenSet

/**
 * The tokens of the signed-in user. [toString] never prints them.
 *
 * @property expiresAtMillis when the access token expires (epoch milliseconds, device clock;
 *   [Long.MAX_VALUE] when 9in didn't say).
 * @property refreshToken rotated by 9in on every refresh; the SDK always keeps the newest one.
 * @property obtainedAtMillis when the tokens were obtained (epoch milliseconds); 0 when unknown.
 */
public class Credentials internal constructor(
    /** The Java SDK's token set these credentials come from (with the verified ID token claims). */
    public val tokenSet: TokenSet,
    public val obtainedAtMillis: Long,
) {
    public val accessToken: String get() = tokenSet.accessToken()
    public val tokenType: String get() = tokenSet.tokenType() ?: "Bearer"
    public val expiresAtMillis: Long get() = tokenSet.expiresAt()?.toEpochMilli() ?: Long.MAX_VALUE
    public val refreshToken: String? get() = tokenSet.refreshToken()
    public val idToken: String? get() = tokenSet.idToken()
    public val scope: String? get() = tokenSet.scope()

    /** The granted scopes. */
    public val scopes: List<String> get() = scope?.split(' ')?.filter { it.isNotEmpty() } ?: emptyList()

    /** True when the access token expires within [leewaySeconds] (at [nowMillis]). */
    @JvmOverloads
    public fun isExpired(leewaySeconds: Long = 0, nowMillis: Long = System.currentTimeMillis()): Boolean =
        expiresAtMillis != Long.MAX_VALUE && expiresAtMillis - leewaySeconds * 1000 <= nowMillis

    override fun toString(): String =
        "Credentials(tokenType=$tokenType, expiresAtMillis=$expiresAtMillis, scope=$scope, refreshToken=${if (refreshToken != null) "…" else "null"}, idToken=${if (idToken != null) "…" else "null"})"
}

/** The signed-in user: the verified claims of the ID token. */
public class NineUser(
    /** Every claim, as JSON values (`String`, `Long`, `Double`, `Boolean`, `List`, `Map`, `null`). */
    public val claims: Map<String, Any?>,
) {
    /** The user's ID at 9in (`sub`). */
    public val id: String get() = claims["sub"] as? String ?: ""
    public val email: String? get() = claims["email"] as? String
    public val emailVerified: Boolean? get() = claims["email_verified"] as? Boolean
    public val name: String? get() = claims["name"] as? String
    public val givenName: String? get() = claims["given_name"] as? String
    public val familyName: String? get() = claims["family_name"] as? String
    public val picture: String? get() = claims["picture"] as? String
    public val phoneNumber: String? get() = claims["phone_number"] as? String
    public val locale: String? get() = claims["locale"] as? String

    /** How the user signed in (`pwd`, `otp`, `social`, `fed`, `link`, `mfa`). */
    public val authenticationMethods: List<String> get() = (claims["amr"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()

    public operator fun get(claim: String): Any? = claims[claim]

    override fun equals(other: Any?): Boolean = other is NineUser && other.claims == claims
    override fun hashCode(): Int = claims.hashCode()
    override fun toString(): String = "NineUser(id=$id, email=$email)"
}
