package io.ninein.android

import android.content.Context
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Sign-in for Android apps with 9in: authorization code flow with PKCE in Custom Tabs, tokens
 * encrypted with an Android Keystore key, refresh with rotation, sign-out.
 *
 * ```
 * val nine = NineClient(context, issuer = "https://acme.9in.io", clientId = "app_…", redirectUri = "com.acme.app:/callback")
 * val user = nine.signIn(activity)          // Custom Tab, PKCE, state, nonce, ID token checks
 * val token = nine.accessToken()            // refreshed (and rotated) when it is about to expire
 * nine.signOut(activity)                    // revokes the refresh token, ends the 9in session
 * ```
 *
 * Create one per app (for example in your `Application` or with your DI framework) and share it:
 * it is safe to use from any thread, and concurrent [accessToken] calls share one refresh.
 * [state] tells you who is signed in, for Compose (`collectAsState()`) or any other UI.
 */
public class NineClient internal constructor(
    public val config: NineConfig,
    private val store: CredentialStore,
    http: HttpTransport,
    private val io: CoroutineDispatcher,
    private val clock: Clock,
) {
    /** A client that keeps its tokens in [store] (any platform; see [MemoryCredentialStore]). */
    @JvmOverloads
    public constructor(config: NineConfig, store: CredentialStore, http: HttpTransport = UrlConnectionTransport()) :
        this(config, store, http, Dispatchers.IO, Clock.SYSTEM)

    /** A client that keeps its tokens encrypted with an Android Keystore key ([KeystoreCredentialStore]). */
    @JvmOverloads
    public constructor(context: Context, config: NineConfig, http: HttpTransport = UrlConnectionTransport()) :
        this(config, KeystoreCredentialStore(context), http)

    /**
     * A client for [issuer] and the application [clientId], with tokens in the Android Keystore.
     *
     * @param redirectUri the callback registered on the application, e.g. `com.acme.app:/callback`
     *   (with `manifestPlaceholders["nineRedirectScheme"] = "com.acme.app"`).
     * @param audience an API identifier, to get access tokens for your API.
     */
    @JvmOverloads
    public constructor(
        context: Context,
        issuer: String,
        clientId: String,
        redirectUri: String,
        audience: String? = null,
        scopes: List<String> = NineConfig.DEFAULT_SCOPES,
    ) : this(context, NineConfig(issuer, clientId, redirectUri, scopes, audience))

    internal val oidc = OidcClient(config, http, io, clock)
    private val scope = CoroutineScope(SupervisorJob() + io)
    private val keyPrefix = "9in:${config.issuer}:${config.clientId}"
    private val credentialsKey = "$keyPrefix:credentials"
    private val pendingKey = "$keyPrefix:pending"

    private val lock = Any()
    private val loaded = CompletableDeferred<Unit>()
    private val signInLock = Mutex()
    private val refreshLock = Mutex()

    @Volatile private var credentials: Credentials? = null
    @Volatile private var pending: PendingLogin? = null

    private val mutableState = MutableStateFlow<AuthState>(AuthState.Loading)

    /** Who is signed in. Starts as [AuthState.Loading] while the stored session is read. */
    public val state: StateFlow<AuthState> = mutableState.asStateFlow()

    /** The signed-in user (the ID token's verified claims), or null. */
    public val user: NineUser? get() = (mutableState.value as? AuthState.SignedIn)?.user

    /** True when a user is signed in (a valid access token or a refresh token is stored). */
    public val isSignedIn: Boolean get() = mutableState.value is AuthState.SignedIn

    init {
        scope.launch { load() }
    }

    private fun load() {
        try {
            val stored = store.read(credentialsKey)?.let { Credentials.fromJson(it) }
            pending = store.read(pendingKey)?.let { PendingLogin.fromJson(it) }
            if (stored != null && (stored.refreshToken != null || !stored.isExpired(0, clock.nowMillis()))) {
                credentials = stored
                mutableState.value = AuthState.SignedIn(userFrom(stored.idToken))
            } else {
                if (stored != null) store.write(credentialsKey, null)
                mutableState.value = AuthState.SignedOut
            }
        } catch (e: Exception) {
            // An unreadable store (a lost Keystore key, corrupt data) means nobody is signed in.
            credentials = null
            mutableState.value = AuthState.SignedOut
        } finally {
            loaded.complete(Unit)
        }
        AuthorizationBroker.register(this)
    }

    private suspend fun awaitLoaded() = loaded.await()

    // ---------------------------------------------------------------------------------------------
    // Sign-in

    /**
     * Signs the user in: opens the hosted sign-in page in a Custom Tab (or the browser), waits for
     * the redirect, checks it (state, issuer), exchanges the code with the PKCE verifier, verifies
     * the ID token and stores the tokens. Returns the signed-in user.
     *
     * @param context an Activity (or a context that wraps one, such as Compose's `LocalContext`).
     * @throws NineException [NineException.CANCELED] when the user closes the browser, an OAuth
     *   error such as [NineException.ACCESS_DENIED], or a failed check.
     */
    @JvmOverloads
    public suspend fun signIn(context: Context, options: SignInOptions = SignInOptions()): NineUser =
        signIn(CustomTabsBrowser(context), options)

    /** Opens the sign-up form directly (`prompt=create`); otherwise the same as [signIn]. */
    @JvmOverloads
    public suspend fun signUp(context: Context, options: SignInOptions = SignInOptions()): NineUser =
        signUp(CustomTabsBrowser(context), options)

    /** [signIn] with your own [BrowserStep] (tests, other platforms). */
    public suspend fun signIn(browser: BrowserStep, options: SignInOptions = SignInOptions()): NineUser =
        authorize(browser, options, signUp = false)

    /** [signUp] with your own [BrowserStep]. */
    public suspend fun signUp(browser: BrowserStep, options: SignInOptions = SignInOptions()): NineUser =
        authorize(browser, options, signUp = true)

    private suspend fun authorize(browser: BrowserStep, options: SignInOptions, signUp: Boolean): NineUser {
        awaitLoaded()
        val request = oidc.authorizationRequest(options, signUp)
        withContext(io) { savePending(request.pending) }
        val callback = try {
            browser.open(request.url, config.redirectUri)
        } catch (e: NineException) {
            if (e.code == NineException.CANCELED) withContext(io) { clearPending(request.pending.state) }
            throw e
        }
        // Once 9in has redirected back, finish even if the caller goes away (a rotation, say):
        // the code is single-use, and [state] tells the UI the outcome.
        return withContext(NonCancellable) { handleRedirect(callback) }
    }

    /**
     * Completes a sign-in from the redirect URL 9in sent the browser to. [signIn] calls this
     * itself; call it when your app receives the redirect some other way (your own activity for an
     * App Link, say). The redirect must belong to the sign-in in progress (`state`), and is
     * accepted only once.
     */
    public suspend fun handleRedirect(url: String): NineUser {
        awaitLoaded()
        return withContext(io) {
            signInLock.withLock {
                val state = OidcClient.queryParams(url)["state"]
                val current = pending
                val matches = current != null && state != null && Crypto.safeEquals(current.state, state)
                // Single use: a redirect for this sign-in consumes it, whatever the outcome.
                if (matches) clearPending(current!!.state)
                val result = oidc.exchangeCode(url, if (matches) current else null)
                val user = NineUser(result.claims ?: emptyMap())
                // After any refresh of the previous session, so its result can't overwrite this one.
                refreshLock.withLock { saveCredentials(result.credentials, user) }
                user
            }
        }
    }

    /**
     * Called by the Android redirect handling when a redirect arrives that nobody is waiting for
     * (the caller was cancelled, or the process was restarted while the browser was open).
     */
    internal fun offerRedirect(url: String): Boolean {
        val state = OidcClient.queryParams(url)["state"] ?: return false
        val current = pending ?: return false
        if (!Crypto.safeEquals(current.state, state)) return false
        scope.launch {
            try {
                handleRedirect(url)
            } catch (e: NineException) {
                // Nobody is waiting for this sign-in; [state] stays as it was.
            }
        }
        return true
    }

    // ---------------------------------------------------------------------------------------------
    // Tokens

    /**
     * A valid access token. When it expires within [minValiditySeconds], it is refreshed first
     * (9in rotates the refresh token; the new one is stored). Concurrent callers share one refresh.
     *
     * @throws NineException [NineException.LOGIN_REQUIRED] when nobody is signed in, or the session
     *   ended (the user is then signed out); [NineException.NETWORK_ERROR] when 9in can't be
     *   reached (the session is kept).
     */
    @JvmOverloads
    public suspend fun accessToken(minValiditySeconds: Long = 60): String {
        awaitLoaded()
        credentials?.let { if (!it.isExpired(it.margin(minValiditySeconds), clock.nowMillis())) return it.accessToken }
        return refreshLock.withLock {
            val current = credentials ?: throw NineException(NineException.LOGIN_REQUIRED, "nobody is signed in")
            if (!current.isExpired(current.margin(minValiditySeconds), clock.nowMillis())) return@withLock current.accessToken
            if (current.refreshToken == null) {
                // Nothing to refresh with: the token is good until it actually expires.
                if (!current.isExpired(0, clock.nowMillis())) return@withLock current.accessToken
                withContext(io) { clearSession() }
                throw NineException(NineException.LOGIN_REQUIRED, "the access token expired and there is no refresh token (request offline_access)")
            }
            withContext(NonCancellable + io) { refreshNow(current) }.accessToken
        }
    }

    /** At most half the token's lifetime, so short-lived tokens aren't refreshed on every call. */
    private fun Credentials.margin(minValiditySeconds: Long): Long {
        val lifetime = (expiresAtMillis - obtainedAtMillis) / 1000
        return if (obtainedAtMillis > 0 && lifetime > 0) minOf(minValiditySeconds, lifetime / 2) else minValiditySeconds
    }

    /** Refreshes the tokens now, whether or not the access token is about to expire. */
    public suspend fun refresh(): Credentials {
        awaitLoaded()
        return refreshLock.withLock {
            val current = credentials ?: throw NineException(NineException.LOGIN_REQUIRED, "nobody is signed in")
            if (current.refreshToken == null) throw NineException(NineException.LOGIN_REQUIRED, "there is no refresh token (request offline_access)")
            withContext(NonCancellable + io) { refreshNow(current) }
        }
    }

    private suspend fun refreshNow(current: Credentials): Credentials {
        try {
            val result = oidc.refresh(current, user?.id?.takeIf { it.isNotEmpty() })
            val newUser = result.claims?.let { NineUser(it) } ?: user ?: userFrom(result.credentials.idToken)
            saveCredentials(result.credentials, newUser)
            return result.credentials
        } catch (e: NineException) {
            when (e.code) {
                NineException.INVALID_GRANT -> {
                    // Revoked, expired, or the session ended: the user has to sign in again.
                    clearSession()
                    throw NineException(NineException.LOGIN_REQUIRED, "the session ended; sign in again", e.status, e)
                }
                NineException.INVALID_ID_TOKEN -> {
                    clearSession()
                    throw e
                }
                else -> throw e
            }
        }
    }

    /** The stored tokens (the access token may have expired; use [accessToken] for a valid one). */
    public suspend fun credentials(): Credentials? {
        awaitLoaded()
        return credentials
    }

    /** The user's current profile from 9in's userinfo endpoint. */
    public suspend fun userInfo(): Map<String, Any?> = oidc.userInfo(accessToken())

    // ---------------------------------------------------------------------------------------------
    // Sign-out

    /**
     * Signs the user out: forgets the tokens, revokes the refresh token and ends the 9in session
     * in the browser (otherwise the next sign-in is instant, as single sign-on).
     *
     * @param postLogoutRedirectUri where 9in sends the browser afterwards, so the Custom Tab closes
     *   by itself: one of the application's **Allowed logout URLs**, such as your redirect URI.
     *   Without it, 9in shows a "You're signed out" page that the user closes.
     */
    @JvmOverloads
    public suspend fun signOut(context: Context, postLogoutRedirectUri: String? = null): Unit =
        signOut(CustomTabsBrowser(context), postLogoutRedirectUri)

    /**
     * Signs the user out. Without a [browser], only in this app: the tokens are forgotten and the
     * refresh token is revoked, but the 9in session in the browser stays.
     */
    @JvmOverloads
    public suspend fun signOut(browser: BrowserStep? = null, postLogoutRedirectUri: String? = null) {
        awaitLoaded()
        val current = withContext(io) {
            refreshLock.withLock { credentials.also { clearSession() } }
        }
        withContext(NonCancellable + io) {
            val token = current?.refreshToken
            try {
                if (token != null) oidc.revoke(token, "refresh_token") else current?.let { oidc.revoke(it.accessToken, "access_token") }
            } catch (e: NineException) {
                // Signing out never fails because 9in can't be reached; the tokens are gone here.
            }
        }
        if (browser != null) {
            val url = oidc.endSessionUrl(current?.idToken, postLogoutRedirectUri, state = null)
            try {
                browser.open(url, postLogoutRedirectUri ?: config.redirectUri)
            } catch (e: NineException) {
                if (e.code != NineException.CANCELED) throw e
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Storage

    private fun savePending(login: PendingLogin) = synchronized(lock) {
        persist(pendingKey, login.toJson())
        pending = login
    }

    private fun clearPending(state: String) = synchronized(lock) {
        if (pending?.state == state) {
            pending = null
            forget(pendingKey)
        }
    }

    private fun saveCredentials(value: Credentials, user: NineUser) = synchronized(lock) {
        // Memory first: after a refresh the old refresh token is spent, so the new one must be kept
        // for this run even if the store fails.
        credentials = value
        mutableState.value = AuthState.SignedIn(user)
        persist(credentialsKey, value.toJson())
    }

    private fun clearSession() = synchronized(lock) {
        credentials = null
        mutableState.value = AuthState.SignedOut
        forget(credentialsKey)
    }

    private fun persist(key: String, value: String) {
        try {
            store.write(key, value)
        } catch (e: Exception) {
            throw NineException(NineException.STORAGE_ERROR, "could not save to the credential store", cause = e)
        }
    }

    /** Deleting is best effort: the session is over in memory either way. */
    private fun forget(key: String) {
        try {
            store.write(key, null)
        } catch (e: Exception) {
            // Nothing better to do; an unreadable leftover is dropped on the next start.
        }
    }

    private fun userFrom(idToken: String?): NineUser {
        if (idToken == null) return NineUser(emptyMap())
        return try {
            NineUser(Jwt.decode(idToken).payload)
        } catch (e: IllegalArgumentException) {
            NineUser(emptyMap())
        }
    }
}
