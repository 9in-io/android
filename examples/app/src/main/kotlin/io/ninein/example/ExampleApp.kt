package io.ninein.example

import android.app.Application
import io.ninein.android.NineClient

/** One NineClient for the whole app. */
class ExampleApp : Application() {
    lateinit var nine: NineClient
        private set

    override fun onCreate() {
        super.onCreate()
        nine = NineClient(
            context = this,
            issuer = BuildConfig.NINE_ISSUER,
            clientId = BuildConfig.NINE_CLIENT_ID,
            redirectUri = BuildConfig.NINE_REDIRECT_URI,
        )
    }
}
