
package com.darkshadow.sideloadatv.auth

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import uniffi.sideloadatv_ffi.GrandslamSession
import uniffi.sideloadatv_ffi.GsException
import uniffi.sideloadatv_ffi.GsLoginState

private sealed class LoginStage {
    object Form : LoginStage()
    object AwaitingDeviceCode : LoginStage()
    object AwaitingSmsCode : LoginStage()
    data class LoggedIn(val name: String) : LoginStage()
    data class Failed(val message: String) : LoginStage()
}

@Composable
fun GrandslamLoginSection(
    session: GrandslamSession,
    modifier: Modifier = Modifier,
    onLoggedIn: () -> Unit = {},
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var stage by remember { mutableStateOf<LoginStage>(LoginStage.Form) }
    var statusText by remember { mutableStateOf("") }
    var isBusy by remember { mutableStateOf(false) }

    suspend fun handleState(state: GsLoginState) {
        when (state) {
            is GsLoginState.LoggedIn -> {
                val name = runCatching { session.displayName() }.getOrDefault("(name unavailable)")
                stage = LoginStage.LoggedIn(name)
                statusText = "Logged in"
                onLoggedIn()
            }
            is GsLoginState.NeedsDevice2fa -> {
                statusText = "Sending 2FA push to your trusted devices..."
                handleState(session.send2faToDevices())
            }
            is GsLoginState.Needs2faVerification -> {
                stage = LoginStage.AwaitingDeviceCode
                statusText = "Enter the code shown on your trusted device"
            }
            is GsLoginState.NeedsSms2fa -> {
                statusText = "Fetching trusted phone numbers..."
                val ids = session.trustedPhoneIds()
                val firstId = ids.firstOrNull()?.substringBefore(":")?.toUIntOrNull()
                if (firstId == null) {
                    stage = LoginStage.Failed("No trusted phone numbers available for SMS 2FA")
                } else {
                    handleState(session.sendSms2faToDevices(firstId))
                }
            }
            is GsLoginState.NeedsSmsVerification -> {
                stage = LoginStage.AwaitingSmsCode
                statusText = "Enter the SMS code sent to your phone"
            }
            is GsLoginState.NeedsExtraStep -> {
                stage = LoginStage.Failed("Unhandled Apple auth step: ${state.step}")
            }
            is GsLoginState.NeedsLogin -> {
                statusText = "2FA verified, completing login..."
                handleState(session.loginEmailPass(context.filesDir.absolutePath, email, password))
            }
        }
    }

    fun runFfiCall(block: suspend () -> Unit) {
        isBusy = true
        scope.launch(Dispatchers.IO) {
            runCatching { block() }
                .onFailure {
                    val msg = (it as? GsException.Message)?.v1 ?: it.message ?: it.toString()
                    stage = LoginStage.Failed(msg)
                }
            isBusy = false
        }
    }

    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(text = "Apple ID Login", style = MaterialTheme.typography.titleMedium)

        when (val current = stage) {
            is LoginStage.Form -> {
                OutlinedTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = { Text("Apple ID") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    enabled = !isBusy && email.isNotBlank() && password.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                    onClick = {
                        runFfiCall {
                            handleState(session.loginEmailPass(context.filesDir.absolutePath, email, password))
                        }
                    },
                ) { Text("Log in") }
            }
            is LoginStage.AwaitingDeviceCode, is LoginStage.AwaitingSmsCode -> {
                OutlinedTextField(
                    value = code,
                    onValueChange = { code = it },
                    label = { Text("Verification code") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    enabled = !isBusy && code.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                    onClick = {
                        runFfiCall {
                            val result = if (current is LoginStage.AwaitingSmsCode) {
                                session.verifySms2fa(code)
                            } else {
                                session.verify2fa(code)
                            }
                            handleState(result)
                        }
                    },
                ) { Text("Verify") }
            }
            is LoginStage.LoggedIn -> Text(text = "Signed in as ${current.name}")
            is LoginStage.Failed -> Text(
                text = "Error: ${current.message}",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        if (statusText.isNotBlank()) {
            Text(
                text = statusText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
