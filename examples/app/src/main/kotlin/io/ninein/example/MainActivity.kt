package io.ninein.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.ninein.android.AuthState
import io.ninein.android.NineClient
import io.ninein.android.NineException
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val nine = (application as ExampleApp).nine
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) { Home(nine) }
            }
        }
    }
}

@Composable
fun Home(nine: NineClient) {
    val state by nine.state.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var message by remember { mutableStateOf<String?>(null) }

    // Runs a 9in call and shows its error, if any (closing the browser is not an error).
    fun run(action: suspend () -> Unit) {
        scope.launch {
            message = null
            try {
                action()
            } catch (e: NineException) {
                if (e.code != NineException.CANCELED) message = e.message
            }
        }
    }

    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("9in example", style = MaterialTheme.typography.headlineSmall)
        when (val s = state) {
            AuthState.Loading -> CircularProgressIndicator()
            AuthState.SignedOut -> {
                Text("You're signed out.")
                Button(onClick = { run { nine.signIn(context) } }) { Text("Sign in") }
                OutlinedButton(onClick = { run { nine.signUp(context) } }) { Text("Create an account") }
            }
            is AuthState.SignedIn -> {
                Text("Signed in as ${s.user.email ?: s.user.id}")
                Button(onClick = {
                    run {
                        val info = nine.userInfo()
                        message = "userinfo: ${info["email"] ?: info["sub"]}"
                    }
                }) { Text("Call userinfo") }
                Button(onClick = {
                    run {
                        nine.refresh()
                        message = "Tokens refreshed (the refresh token was rotated)."
                    }
                }) { Text("Refresh tokens") }
                OutlinedButton(onClick = { run { nine.signOut(context, postLogoutRedirectUri = BuildConfig.NINE_REDIRECT_URI) } }) {
                    Text("Sign out")
                }
            }
        }
        message?.let { Text(it, color = MaterialTheme.colorScheme.secondary) }
    }
}
