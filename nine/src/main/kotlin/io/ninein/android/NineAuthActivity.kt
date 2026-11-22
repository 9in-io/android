package io.ninein.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle

/**
 * Runs one browser step, invisibly: opens the browser, then reports what happened once the user
 * is back. Either [NineRedirectActivity] brings the redirect (delivered through [onNewIntent]), or
 * the activity is resumed without one, which means the user closed the browser.
 *
 * It is `singleTask`, like AppAuth's management activity: the redirect activity brings it back
 * with `CLEAR_TOP`, which also removes the Custom Tab from the back stack.
 */
internal class NineAuthActivity : Activity() {
    private var requestId: String? = null
    private var browserIntent: Intent? = null
    private var browserStarted = false
    private var delivered = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {
            requestId = savedInstanceState.getString(EXTRA_REQUEST_ID)
            browserIntent = savedInstanceState.parcelable(EXTRA_BROWSER_INTENT)
            browserStarted = savedInstanceState.getBoolean(KEY_BROWSER_STARTED)
            delivered = savedInstanceState.getBoolean(KEY_DELIVERED)
        } else {
            readRequest(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.hasExtra(EXTRA_REQUEST_ID)) {
            // A new browser step while this one was open: this one is over.
            deliver(AuthorizationBroker.Result.Canceled)
            readRequest(intent)
        }
        setIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        val redirect = intent?.data
        val browser = browserIntent
        when {
            redirect != null -> {
                deliver(AuthorizationBroker.Result.Redirect(redirect.toString()))
                finish()
            }
            !browserStarted && browser != null -> {
                browserStarted = true
                try {
                    startActivity(browser)
                } catch (e: ActivityNotFoundException) {
                    deliver(AuthorizationBroker.Result.Failed(NineException(NineException.BROWSER_NOT_FOUND, "no browser can open the page", cause = e)))
                    finish()
                }
            }
            else -> {
                // Back from the browser without a redirect: the user closed it.
                deliver(AuthorizationBroker.Result.Canceled)
                finish()
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(EXTRA_REQUEST_ID, requestId)
        outState.putParcelable(EXTRA_BROWSER_INTENT, browserIntent)
        outState.putBoolean(KEY_BROWSER_STARTED, browserStarted)
        outState.putBoolean(KEY_DELIVERED, delivered)
    }

    override fun onDestroy() {
        // Finished without an outcome (not recreated for a configuration change): nothing is coming.
        if (isFinishing && !isChangingConfigurations) deliver(AuthorizationBroker.Result.Canceled)
        super.onDestroy()
    }

    private fun readRequest(intent: Intent?) {
        requestId = intent?.getStringExtra(EXTRA_REQUEST_ID)
        browserIntent = intent?.parcelable(EXTRA_BROWSER_INTENT)
        browserStarted = false
        delivered = false
    }

    private fun deliver(result: AuthorizationBroker.Result) {
        if (delivered) return
        delivered = true
        AuthorizationBroker.deliver(requestId, result)
    }

    internal companion object {
        const val EXTRA_REQUEST_ID = "io.ninein.android.REQUEST_ID"
        const val EXTRA_BROWSER_INTENT = "io.ninein.android.BROWSER_INTENT"
        private const val KEY_BROWSER_STARTED = "io.ninein.android.BROWSER_STARTED"
        private const val KEY_DELIVERED = "io.ninein.android.DELIVERED"

        fun startIntent(context: Context, requestId: String, browser: Intent): Intent =
            Intent(context, NineAuthActivity::class.java)
                .putExtra(EXTRA_REQUEST_ID, requestId)
                .putExtra(EXTRA_BROWSER_INTENT, browser)

        fun redirectIntent(context: Context, redirect: Uri): Intent =
            Intent(context, NineAuthActivity::class.java)
                .setData(redirect)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    }
}

@Suppress("DEPRECATION")
private inline fun <reified T : android.os.Parcelable> Bundle.parcelable(key: String): T? =
    if (Build.VERSION.SDK_INT >= 33) getParcelable(key, T::class.java) else getParcelable(key) as? T

@Suppress("DEPRECATION")
private inline fun <reified T : android.os.Parcelable> Intent.parcelable(key: String): T? =
    if (Build.VERSION.SDK_INT >= 33) getParcelableExtra(key, T::class.java) else getParcelableExtra(key) as? T

/**
 * Receives the redirect from 9in (your `nineRedirectScheme`, or an App Link you route to it) and
 * hands it to the browser step that is waiting for it. You never start it yourself.
 *
 * For an https redirect (App Links), add an intent filter for your callback URL to this activity
 * in your app's manifest (see the README).
 */
public class NineRedirectActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val redirect = intent?.data
        if (redirect != null) startActivity(NineAuthActivity.redirectIntent(this, redirect))
        finish()
    }
}
