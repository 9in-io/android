package io.ninein.android

import kotlinx.coroutines.CompletableDeferred
import java.lang.ref.WeakReference

/**
 * Hands the outcome of a browser step (the redirect, or "the user closed the browser") from the
 * activity that saw it to the coroutine waiting in [CustomTabsBrowser.open].
 *
 * A redirect that nobody waits for any more (the caller was cancelled, or the process was
 * restarted while the browser was open) is offered to the live [NineClient]s, which complete the
 * sign-in it belongs to (matched by `state`). One that arrives before its client exists is kept for
 * a few minutes and offered to clients as they are created.
 */
internal object AuthorizationBroker {
    sealed class Result {
        class Redirect(val url: String) : Result()
        object Canceled : Result()
        class Failed(val error: NineException) : Result()
    }

    private const val UNCLAIMED_TTL = 10 * 60_000L
    private val waiting = HashMap<String, CompletableDeferred<Result>>()
    private val clients = ArrayList<WeakReference<NineClient>>()
    private var unclaimed: Pair<String, Long>? = null

    @Synchronized
    fun await(requestId: String): CompletableDeferred<Result> = CompletableDeferred<Result>().also { waiting[requestId] = it }

    /** The waiting coroutine went away: a later redirect for [requestId] is offered to the clients. */
    @Synchronized
    fun abandon(requestId: String) {
        waiting.remove(requestId)
    }

    fun deliver(requestId: String?, result: Result) {
        val deferred = synchronized(this) { requestId?.let { waiting.remove(it) } }
        if (deferred != null && deferred.complete(result)) return
        if (result is Result.Redirect) offer(result.url)
    }

    private fun offer(url: String) {
        val live = synchronized(this) {
            clients.removeAll { it.get() == null }
            clients.mapNotNull { it.get() }
        }
        if (live.any { it.offerRedirect(url) }) return
        synchronized(this) { unclaimed = url to System.currentTimeMillis() }
    }

    fun register(client: NineClient) {
        val candidate = synchronized(this) {
            clients.removeAll { it.get() == null || it.get() === client }
            clients.add(WeakReference(client))
            unclaimed?.takeIf { System.currentTimeMillis() - it.second < UNCLAIMED_TTL }
        }
        if (candidate != null && client.offerRedirect(candidate.first)) {
            synchronized(this) { if (unclaimed === candidate) unclaimed = null }
        }
    }

    /** For tests. */
    @Synchronized
    internal fun reset() {
        waiting.clear()
        clients.clear()
        unclaimed = null
    }
}
