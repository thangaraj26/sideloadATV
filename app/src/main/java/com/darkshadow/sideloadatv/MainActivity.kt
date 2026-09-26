package com.darkshadow.sideloadatv

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
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
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.darkshadow.sideloadatv.auth.AccountScreen
import com.darkshadow.sideloadatv.auth.AppleIdentity
import com.darkshadow.sideloadatv.auth.clearStoredAccount
import com.darkshadow.sideloadatv.auth.loadStoredAccount
import com.darkshadow.sideloadatv.auth.saveStoredAccount
import com.darkshadow.sideloadatv.discovery.DevicesScreen
import com.darkshadow.sideloadatv.discovery.MdnsDiscovery
import com.darkshadow.sideloadatv.pairing.DeviceDetailScreen
import com.darkshadow.sideloadatv.ui.theme.SideloadATVTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private lateinit var discovery: MdnsDiscovery

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        discovery = MdnsDiscovery(this)
        enableEdgeToEdge()
        setContent {
            SideloadATVTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    AppNavHost(discovery = discovery)
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        discovery.stop()
    }
}

@Composable
private fun AppNavHost(discovery: MdnsDiscovery, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val navController = rememberNavController()
    val scope = rememberCoroutineScope()

    // Restore from encrypted storage synchronously in remember so the nav host
    // renders immediately without a loading gate. Token validity is not checked
    // here -- an expired token surfaces as an error at sign time, at which point
    // the user can re-login from the Account screen.
    var identity: AppleIdentity? by remember {
        val stored = loadStoredAccount(context)
        mutableStateOf<AppleIdentity?>(stored?.let { AppleIdentity.Restored(it) })
    }

    NavHost(navController = navController, startDestination = "devices", modifier = modifier) {
        composable("devices") {
            DevicesScreen(
                discovery = discovery,
                identity = identity,
                onOpenAccount = { navController.navigate("account") },
                onOpenDevice = { device -> navController.navigate("device/${device.serviceName}") },
            )
        }
        composable("account") {
            AccountScreen(
                identity = identity,
                onBack = { navController.popBackStack() },
                onSignedIn = { live ->
                    identity = live
                    scope.launch {
                        runCatching { live.session.exportAccount() }
                            .onSuccess { saveStoredAccount(context, it) }
                    }
                    navController.popBackStack()
                },
                onSignOut = {
                    identity = null
                    clearStoredAccount(context)
                    navController.popBackStack()
                },
            )
        }
        composable(
            "device/{serviceName}",
            arguments = listOf(navArgument("serviceName") { type = NavType.StringType }),
        ) { backStackEntry ->
            val serviceName = backStackEntry.arguments?.getString("serviceName")
            val devices by discovery.devices.collectAsState()
            val device = devices.firstOrNull { it.serviceName == serviceName }
            if (device != null) {
                DeviceDetailScreen(
                    device = device,
                    identity = identity,
                    onBack = { navController.popBackStack() },
                    onSessionExpired = {
                        identity = null
                        clearStoredAccount(context)
                        navController.popBackStack()
                    },
                )
            } else {
                Text(text = "Device no longer visible -- go back and rediscover it.")
            }
        }
    }
}
