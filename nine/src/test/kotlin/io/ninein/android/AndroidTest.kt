package io.ninein.android

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Bundle
import android.os.Looper
import androidx.browser.customtabs.CustomTabsService
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.io.File
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

private const val TEST_SCHEME = "io.ninein.android.test"
private const val TEST_REDIRECT = "$TEST_SCHEME:/callback"

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 30, 37])
class KeystoreCredentialStoreTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val dir get() = File(context.noBackupFilesDir, "test-store")

    private fun store(secret: SecretKey = key) = KeystoreCredentialStore(context, { secret }, "test-store")

    @Test
    fun `values round trip and can be deleted`() {
        val store = store()
        assertNull(store.read("a"))
        store.write("a", "first")
        store.write("b", "ünïcødé ✓")
        assertEquals("first", store.read("a"))
        assertEquals("ünïcødé ✓", store().read("b")) // another instance, same files
        store.write("a", "second")
        assertEquals("second", store.read("a"))
        store.write("a", null)
        assertNull(store.read("a"))
        assertEquals("ünïcødé ✓", store.read("b"))
    }

    @Test
    fun `files are encrypted, in the no-backup directory, and named by hash`() {
        val secret = "rt_super_secret_refresh_token"
        store().write("9in:https://acme.9in.io:app:credentials", """{"refresh_token":"$secret"}""")
        val files = dir.listFiles()!!.filter { !it.name.endsWith(".bak") }
        assertEquals(1, files.size)
        assertFalse(files[0].name.contains("acme") || files[0].name.contains(":"))
        assertFalse(String(files[0].readBytes(), Charsets.ISO_8859_1).contains(secret))
        assertTrue(files[0].absolutePath.startsWith(context.noBackupFilesDir.absolutePath))
    }

    @Test
    fun `tampered data reads as absent and is deleted`() {
        val store = store()
        store.write("a", "value-a")
        val file = dir.listFiles()!!.single()
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertNull(store.read("a"))
        assertFalse(file.exists())
        // Garbage is handled the same way.
        store.write("b", "value-b")
        dir.listFiles()!!.single().writeBytes(byteArrayOf(9, 9, 9))
        assertNull(store.read("b"))
    }

    @Test
    fun `a temporary Keystore failure keeps the data`() {
        store().write("a", "value-a")
        var fail = true
        val flaky = KeystoreCredentialStore(context, { if (fail) throw java.security.KeyStoreException("keystore busy") else key }, "test-store")
        assertTrue(runCatching { flaky.read("a") }.exceptionOrNull() is java.security.KeyStoreException)
        fail = false
        assertEquals("value-a", flaky.read("a"))
    }

    @Test
    fun `data written with another key reads as absent`() {
        store().write("y", "value-y")
        // The Keystore key was lost (or the files came from another device).
        assertNull(store(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()).read("y"))
    }

    @Test
    fun `a value under one name can't be read under another`() {
        val store = store()
        store.write("x", "value-x")
        val before = dir.listFiles()!!.map { it.name }.toSet()
        store.write("y", "value-y")
        val yName = (dir.listFiles()!!.map { it.name }.toSet() - before).single()
        val xName = before.single()
        File(dir, yName).writeBytes(File(dir, xName).readBytes())
        assertNull(store.read("y"))
        assertEquals("value-x", store.read("x"))
    }

    @Test
    fun `NineClient keeps its session in it`() = runBlocking<Unit> {
        AuthorizationBroker.reset()
        val fake = FakeNine()
        val user = fake.client(store()).signIn(fake.browser())
        val restarted = fake.client(store())
        assertEquals(AuthState.SignedIn(user), restarted.state.first { it != AuthState.Loading })
        assertNull("another key can't read it", fake.client(store(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey())).state.first { it != AuthState.Loading }.let { (it as? AuthState.SignedIn)?.user })
    }

    @Test
    fun `without the Android Keystore the client reports a storage error`() = runBlocking<Unit> {
        // Robolectric has no AndroidKeyStore provider, like a device whose Keystore is broken.
        AuthorizationBroker.reset()
        val fake = FakeNine()
        val nine = NineClient(NineConfig(fake.issuer, fake.clientId, REDIRECT), KeystoreCredentialStore(context), fake)
        assertEquals(AuthState.SignedOut, nine.state.first { it != AuthState.Loading })
        expectNine(NineException.STORAGE_ERROR) { nine.signIn(fake.browser()) }
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 30, 37])
class BrowserFlowTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        AuthorizationBroker.reset()
    }

    /** Installs a fake browser app: an activity for https links and, optionally, a Custom Tabs service. */
    private fun installBrowser(customTabs: Boolean) {
        val pm = shadowOf(context.packageManager)
        val activity = ComponentName("com.example.browser", "com.example.browser.Main")
        pm.addActivityIfNotPresent(activity)
        pm.addIntentFilterForActivity(
            activity,
            IntentFilter(Intent.ACTION_VIEW).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
                addCategory(Intent.CATEGORY_DEFAULT)
                addDataScheme("http")
                addDataScheme("https")
            },
        )
        if (customTabs) {
            val service = ComponentName("com.example.browser", "com.example.browser.TabsService")
            pm.addServiceIfNotPresent(service)
            pm.addIntentFilterForService(service, IntentFilter(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION))
        }
    }

    @Test
    fun `the redirect scheme from the manifest placeholder opens NineRedirectActivity`() {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("$TEST_REDIRECT?code=x&state=y")).addCategory(Intent.CATEGORY_BROWSABLE)
        val match = context.packageManager.queryIntentActivities(intent, 0).map { it.activityInfo.name }
        assertEquals(listOf(NineRedirectActivity::class.java.name), match)
    }

    @Test
    fun `NineRedirectActivity hands the redirect to NineAuthActivity and finishes`() {
        val uri = Uri.parse("$TEST_REDIRECT?code=a&state=b")
        val activity = Robolectric.buildActivity(NineRedirectActivity::class.java, Intent(Intent.ACTION_VIEW, uri)).create().get()
        val next = shadowOf(activity).nextStartedActivity
        assertEquals(NineAuthActivity::class.java.name, next.component!!.className)
        assertEquals(uri, next.data)
        assertTrue(next.flags and Intent.FLAG_ACTIVITY_CLEAR_TOP != 0)
        assertTrue(next.flags and Intent.FLAG_ACTIVITY_SINGLE_TOP != 0)
        assertTrue(activity.isFinishing)
        // Without data it does nothing.
        val empty = Robolectric.buildActivity(NineRedirectActivity::class.java, Intent(Intent.ACTION_VIEW)).create().get()
        assertNull(shadowOf(empty).nextStartedActivity)
        assertTrue(empty.isFinishing)
    }

    private fun startAuth(requestId: String, url: String = "https://acme.9in.test/oauth/authorize?x=1"): Pair<ActivityController<NineAuthActivity>, Intent> {
        val browser = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        val controller = Robolectric.buildActivity(NineAuthActivity::class.java, NineAuthActivity.startIntent(context, requestId, browser)).setup()
        return controller to browser
    }

    private fun ActivityController<NineAuthActivity>.backFromBrowser(redirect: String? = null) {
        pause().stop()
        if (redirect != null) newIntent(NineAuthActivity.redirectIntent(context, Uri.parse(redirect)))
        restart().start().resume()
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `NineAuthActivity opens the browser, then reports the redirect`() {
        val outcome = AuthorizationBroker.await("r1")
        val (controller, browser) = startAuth("r1")
        val started = shadowOf(controller.get()).nextStartedActivity
        assertEquals(browser.data, started.data)
        assertFalse(outcome.isCompleted)
        controller.backFromBrowser("$TEST_REDIRECT?code=c&state=s")
        assertTrue(controller.get().isFinishing)
        assertEquals("$TEST_REDIRECT?code=c&state=s", (outcome.getCompleted() as AuthorizationBroker.Result.Redirect).url)
        controller.destroy() // no second outcome
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `coming back without a redirect means the user closed the browser`() {
        val outcome = AuthorizationBroker.await("r2")
        val (controller, _) = startAuth("r2")
        controller.backFromBrowser()
        assertTrue(controller.get().isFinishing)
        assertTrue(outcome.getCompleted() is AuthorizationBroker.Result.Canceled)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a NineAuthActivity restored after process death does not open the browser twice`() {
        val outcome = AuthorizationBroker.await("r3")
        val (controller, _) = startAuth("r3")
        assertNotNull(shadowOf(controller.get()).nextStartedActivity)
        val saved = Bundle()
        controller.pause().stop().saveInstanceState(saved)
        // The process dies while the browser is open (no more callbacks), and Android recreates the
        // activity from its saved state when the redirect brings the task back.
        val restored = Robolectric.buildActivity(NineAuthActivity::class.java, controller.intent)
            .create(saved).start().restoreInstanceState(saved).postCreate(saved)
        restored.newIntent(NineAuthActivity.redirectIntent(context, Uri.parse("$TEST_REDIRECT?code=c2")))
        restored.resume()
        assertNull("the browser was opened again", shadowOf(restored.get()).nextStartedActivity)
        assertEquals("$TEST_REDIRECT?code=c2", (outcome.getCompleted() as AuthorizationBroker.Result.Redirect).url)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a new browser step ends the one in progress`() {
        val first = AuthorizationBroker.await("old")
        val second = AuthorizationBroker.await("new")
        val (controller, _) = startAuth("old")
        controller.pause().stop()
        controller.newIntent(NineAuthActivity.startIntent(context, "new", Intent(Intent.ACTION_VIEW, Uri.parse("https://acme.9in.test/oauth/authorize?n=2"))))
        controller.restart().start().resume()
        assertTrue(first.getCompleted() is AuthorizationBroker.Result.Canceled)
        assertEquals(Uri.parse("https://acme.9in.test/oauth/authorize?n=2"), shadowOf(controller.get()).nextStartedActivity.data)
        controller.backFromBrowser("$TEST_REDIRECT?code=n")
        assertEquals("$TEST_REDIRECT?code=n", (second.getCompleted() as AuthorizationBroker.Result.Redirect).url)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `finishing early reports canceled`() {
        val outcome = AuthorizationBroker.await("r4")
        val (controller, _) = startAuth("r4")
        controller.get().finish()
        controller.pause().stop().destroy()
        assertTrue(outcome.getCompleted() is AuthorizationBroker.Result.Canceled)
    }

    @Test
    fun `Custom Tabs are used when a browser supports them`() {
        installBrowser(customTabs = true)
        val intent = CustomTabsBrowser.browserIntent(context, "https://acme.9in.test/oauth/authorize?a=b") { it.setUrlBarHidingEnabled(true) }!!
        assertEquals("com.example.browser", intent.`package`)
        assertEquals(Uri.parse("https://acme.9in.test/oauth/authorize?a=b"), intent.data)
        assertTrue(intent.hasExtra("android.support.customtabs.extra.SESSION"))
    }

    @Test
    fun `the plain browser is used otherwise, and no browser is an error`() = runBlocking<Unit> {
        assertNull(CustomTabsBrowser.browserIntent(context, "https://acme.9in.test/oauth/authorize"))
        val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
        val e = runOffMain { CustomTabsBrowser(activity).open("https://acme.9in.test/oauth/authorize", TEST_REDIRECT) }
        assertEquals(NineException.BROWSER_NOT_FOUND, (e.awaitError() as NineException).code)

        installBrowser(customTabs = false)
        val intent = CustomTabsBrowser.browserIntent(context, "https://acme.9in.test/oauth/authorize")!!
        assertEquals(Intent.ACTION_VIEW, intent.action)
        assertNull(intent.`package`)
        assertTrue(intent.hasCategory(Intent.CATEGORY_BROWSABLE))
    }

    /** Runs [block] on a background thread while the test thread runs the main looper. */
    private fun <T> runOffMain(block: suspend () -> T): Deferred<T> = CoroutineScope(Dispatchers.IO).async { block() }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun <T> Deferred<T>.awaitError(): Throwable {
        while (!isCompleted) shadowOf(Looper.getMainLooper()).idle()
        return getCompletionExceptionOrNull() ?: AssertionError("expected an error")
    }

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { "timed out" }
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(5)
        }
    }

    @Test
    fun `sign-in and sign-out through Custom Tabs, end to end`() = runBlocking<Unit> {
        installBrowser(customTabs = true)
        val fake = FakeNine()
        val nine = NineClient(NineConfig(fake.issuer, fake.clientId, TEST_REDIRECT), MemoryCredentialStore(), fake, Dispatchers.IO, Clock.SYSTEM)
        val host = Robolectric.buildActivity(Activity::class.java).setup().get()

        val signIn = runOffMain { nine.signIn(host) }
        var started: Intent? = null
        idleUntil { signIn.isCompleted || shadowOf(host).nextStartedActivity?.also { started = it } != null }
        if (signIn.isCompleted) signIn.await()
        assertEquals(NineAuthActivity::class.java.name, started!!.component!!.className)
        val auth = Robolectric.buildActivity(NineAuthActivity::class.java, started).setup()
        val tab = shadowOf(auth.get()).nextStartedActivity
        assertEquals("com.example.browser", tab.`package`)
        // The user signs in on the hosted page; 9in redirects to the app.
        auth.backFromBrowser(fake.authorize(tab.data.toString()))
        val user = withTimeout(10_000) { signIn.await() }
        assertEquals("usr_alice", user.id)
        assertTrue(nine.isSignedIn)

        val signOut = runOffMain { nine.signOut(host, postLogoutRedirectUri = TEST_REDIRECT) }
        idleUntil { shadowOf(host).nextStartedActivity?.also { started = it } != null }
        val logout = Robolectric.buildActivity(NineAuthActivity::class.java, started).setup()
        val logoutTab = shadowOf(logout.get()).nextStartedActivity
        assertTrue(logoutTab.data.toString().startsWith("${fake.issuer}/oauth/logout?"))
        logout.backFromBrowser(TEST_REDIRECT)
        withTimeout(10_000) { signOut.await() }
        assertFalse(nine.isSignedIn)
        assertEquals(1, fake.revoked.size)
    }

    @Test
    fun `closing the Custom Tab cancels the sign-in`() = runBlocking<Unit> {
        installBrowser(customTabs = true)
        val fake = FakeNine()
        val nine = NineClient(NineConfig(fake.issuer, fake.clientId, TEST_REDIRECT), MemoryCredentialStore(), fake, Dispatchers.IO, Clock.SYSTEM)
        val host = Robolectric.buildActivity(Activity::class.java).setup().get()
        val signIn = runOffMain { nine.signIn(host) }
        var started: Intent? = null
        idleUntil { shadowOf(host).nextStartedActivity?.also { started = it } != null }
        Robolectric.buildActivity(NineAuthActivity::class.java, started).setup().backFromBrowser()
        val e = withTimeout(10_000) { runCatching { signIn.await() }.exceptionOrNull() }
        assertEquals(NineException.CANCELED, (e as NineException).code)
    }

    @Test
    fun `a redirect after the process restarted completes the sign-in`() = runBlocking<Unit> {
        val fake = FakeNine()
        val store = MemoryCredentialStore()
        val before = NineClient(NineConfig(fake.issuer, fake.clientId, TEST_REDIRECT), store, fake, Dispatchers.IO, Clock.SYSTEM)
        val url = CompletableDeferred<String>()
        val job = runOffMain {
            before.signIn(BrowserStep { u, _ ->
                url.complete(u)
                CompletableDeferred<String>().await()
            })
        }
        val redirect = fake.authorize(url.await())
        job.cancel()
        AuthorizationBroker.reset() // the process is gone
        val after = NineClient(NineConfig(fake.issuer, fake.clientId, TEST_REDIRECT), store, fake, Dispatchers.IO, Clock.SYSTEM)
        after.state.first { it != AuthState.Loading }
        // The task was gone too: the redirect starts a fresh NineAuthActivity with no request.
        val auth = Robolectric.buildActivity(NineAuthActivity::class.java, NineAuthActivity.redirectIntent(context, Uri.parse(redirect))).setup()
        assertTrue(auth.get().isFinishing)
        val state = withTimeout(10_000) { after.state.first { it is AuthState.SignedIn } }
        assertEquals("usr_alice", (state as AuthState.SignedIn).user.id)
    }

    @Test
    fun `contexts are unwrapped to their activity`() {
        val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
        assertEquals(activity, android.content.ContextWrapper(android.content.ContextWrapper(activity)).findActivity())
        assertNull(context.findActivity())
    }
}
