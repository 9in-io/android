package io.ninein.android

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore

/**
 * What only a real device can check: the Android Keystore, the platform's signature providers,
 * the installed browsers, and a whole sign-in with the tokens in the Keystore-encrypted store.
 */
@RunWith(AndroidJUnit4::class)
class DeviceTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun clean() {
        AuthorizationBroker.reset()
        File(context.noBackupFilesDir, KeystoreCredentialStore.DIRECTORY).deleteRecursively()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(KeystoreCredentialStore.KEY_ALIAS)
    }

    @Test
    fun keystoreStoreEncryptsWithAKeyInTheAndroidKeystore() {
        val store = KeystoreCredentialStore(context)
        assertNull(store.read("a"))
        store.write("a", "secret-value")
        assertEquals("secret-value", store.read("a"))
        assertEquals("secret-value", KeystoreCredentialStore(context).read("a"))
        val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(keystore.containsAlias(KeystoreCredentialStore.KEY_ALIAS))
        val file = File(context.noBackupFilesDir, KeystoreCredentialStore.DIRECTORY).listFiles()!!.single()
        assertFalse(String(file.readBytes(), Charsets.ISO_8859_1).contains("secret-value"))

        // The key is lost (for example after a restore to a new device): the value reads as absent.
        keystore.deleteEntry(KeystoreCredentialStore.KEY_ALIAS)
        assertNull(KeystoreCredentialStore(context).read("a"))
        assertFalse(file.exists())
        // And the store works again with a new key.
        val again = KeystoreCredentialStore(context)
        again.write("b", "other")
        assertEquals("other", again.read("b"))
        again.write("b", null)
        assertNull(again.read("b"))
    }

    @Test
    fun everyAlgorithmSignsInThroughTheCoreOnThisDevice() = runBlocking<Unit> {
        // The Java core verifies the ID token's signature with this device's providers (PSS in
        // its own code, EC with the platform's curves).
        for (alg in TestKey.ALGORITHMS) {
            val key = try {
                TestKey(alg)
            } catch (e: java.security.GeneralSecurityException) {
                continue // this Android version can't make Ed25519 keys for the test
            }
            AuthorizationBroker.reset()
            val fake = FakeNine(key = key)
            val nine = NineClient(NineConfig(fake.issuer, fake.clientId, "io.ninein.android.test:/callback"), MemoryCredentialStore(), fake)
            assertEquals("$alg on API ${Build.VERSION.SDK_INT}", "usr_alice", nine.signIn(fake.browser()).id)
            assertEquals("$alg refresh on API ${Build.VERSION.SDK_INT}", "usr_alice", nine.refresh().tokenSet.subject())
        }
    }

    @Test
    fun aBrowserCanShowTheSignInPage() {
        val intent = CustomTabsBrowser.browserIntent(context, "https://acme.9in.io/oauth/authorize?client_id=x")
        assertNotNull("no browser on this device", intent)
    }

    @Test
    fun signInKeepsTheSessionInTheKeystoreStore() = runBlocking<Unit> {
        val fake = FakeNine()
        val config = NineConfig(fake.issuer, fake.clientId, "io.ninein.android.test:/callback")
        val nine = NineClient(context, config, fake)
        assertEquals(AuthState.SignedOut, nine.state.first { it != AuthState.Loading })
        val user = nine.signIn(fake.browser())
        assertEquals("usr_alice", user.id)

        val restarted = NineClient(context, config, fake)
        assertEquals(AuthState.SignedIn(user), restarted.state.first { it != AuthState.Loading })
        val refreshed = restarted.refresh()
        assertEquals(refreshed.refreshToken, NineClient(context, config, fake).credentials()!!.refreshToken)

        restarted.signOut()
        assertEquals(AuthState.SignedOut, NineClient(context, config, fake).state.first { it != AuthState.Loading })
    }
}
