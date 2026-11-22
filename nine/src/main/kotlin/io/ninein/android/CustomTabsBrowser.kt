package io.ninein.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.lang.ref.WeakReference
import java.util.UUID

/**
 * The Android [BrowserStep]: shows 9in's pages in a Custom Tab (the user's default browser when it
 * supports them, otherwise any browser that does), or in the browser itself when none does. Never
 * an embedded web view: passwords stay out of your app, password managers work, and the 9in
 * session is shared with the browser (single sign-on).
 *
 * The redirect comes back through [NineRedirectActivity] (your `nineRedirectScheme`, or an App
 * Link you route to it). Closing the tab ends [open] with [NineException.CANCELED].
 *
 * @param context an Activity, or a context that wraps one (Compose's `LocalContext.current`). With
 *   any other context the browser opens in a new task.
 * @param customize changes to the Custom Tab (toolbar colour, animations, …).
 */
public class CustomTabsBrowser @JvmOverloads constructor(
    context: Context,
    private val customize: (CustomTabsIntent.Builder) -> Unit = {},
) : BrowserStep {
    private val appContext: Context = context.applicationContext ?: context
    private val activity = WeakReference(context.findActivity())

    override suspend fun open(url: String, redirectUri: String): String {
        val requestId = UUID.randomUUID().toString()
        val outcome = AuthorizationBroker.await(requestId)
        try {
            withContext(Dispatchers.Main.immediate) {
                val host = activity.get()?.takeUnless { it.isFinishing } ?: appContext
                val browser = browserIntent(host, url, customize)
                    ?: throw NineException(NineException.BROWSER_NOT_FOUND, "no browser is installed")
                val start = NineAuthActivity.startIntent(host, requestId, browser)
                if (host !is Activity) start.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                try {
                    host.startActivity(start)
                } catch (e: ActivityNotFoundException) {
                    throw NineException(NineException.BROWSER_NOT_FOUND, "NineAuthActivity is missing from the manifest", cause = e)
                }
            }
            return when (val result = outcome.await()) {
                is AuthorizationBroker.Result.Redirect -> result.url
                is AuthorizationBroker.Result.Canceled -> throw NineException(NineException.CANCELED, "the browser was closed")
                is AuthorizationBroker.Result.Failed -> throw result.error
            }
        } catch (e: CancellationException) {
            AuthorizationBroker.abandon(requestId)
            throw e
        } catch (e: Exception) {
            AuthorizationBroker.abandon(requestId)
            throw e
        }
    }

    internal companion object {
        /** A Custom Tabs intent for [url], a plain browser intent, or null without a browser. */
        fun browserIntent(context: Context, url: String, customize: (CustomTabsIntent.Builder) -> Unit = {}): Intent? {
            val uri = Uri.parse(url)
            val tabsPackage = CustomTabsClient.getPackageName(context, null)
            if (tabsPackage != null) {
                val builder = CustomTabsIntent.Builder().setShowTitle(true)
                customize(builder)
                return builder.build().intent.apply {
                    setPackage(tabsPackage)
                    data = uri
                }
            }
            val view = Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE)
            return if (view.resolveActivity(context.packageManager) != null) view else null
        }
    }
}

internal fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext?.findActivity()
    else -> null
}
