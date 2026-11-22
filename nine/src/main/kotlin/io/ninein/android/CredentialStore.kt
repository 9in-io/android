package io.ninein.android

/**
 * Where [NineClient] keeps the tokens and the sign-in in progress: a small key-value store of
 * strings. On Android the default is [KeystoreCredentialStore] (AES-GCM with a key in the Android
 * Keystore). Calls happen on a background thread.
 */
public interface CredentialStore {
    /** The value saved under [key], or null. */
    public fun read(key: String): String?

    /** Saves [value] under [key]; null deletes it. */
    public fun write(key: String, value: String?)
}

/** Keeps everything in memory (gone when the process ends). For tests and previews. */
public class MemoryCredentialStore : CredentialStore {
    private val values = HashMap<String, String>()

    @Synchronized
    override fun read(key: String): String? = values[key]

    @Synchronized
    override fun write(key: String, value: String?) {
        if (value == null) values.remove(key) else values[key] = value
    }

    /** The saved keys (for tests). */
    @Synchronized
    public fun keys(): Set<String> = values.keys.toSet()
}

/** Whether someone is signed in. */
public sealed class AuthState {
    /** The stored session is being read (just after the client was created). */
    public object Loading : AuthState() {
        override fun toString(): String = "Loading"
    }

    /** Nobody is signed in. */
    public object SignedOut : AuthState() {
        override fun toString(): String = "SignedOut"
    }

    /** [user] is signed in: there is a valid access token or a refresh token. */
    public class SignedIn(public val user: NineUser) : AuthState() {
        override fun equals(other: Any?): Boolean = other is SignedIn && other.user == user
        override fun hashCode(): Int = user.hashCode()
        override fun toString(): String = "SignedIn($user)"
    }
}

/**
 * Shows a 9in page (sign-in, sign-up or sign-out) in a browser and reports where it ended. On
 * Android, [CustomTabsBrowser] does this with Custom Tabs; tests can drive the hosted pages with
 * an HTTP client instead.
 */
public fun interface BrowserStep {
    /**
     * Opens [url] and returns the URL the browser was sent to once it starts with [redirectUri]
     * (with `code`, `state` and `iss`, or `error`). Throws [NineException] with
     * [NineException.CANCELED] when the user closes the browser first.
     */
    public suspend fun open(url: String, redirectUri: String): String
}
