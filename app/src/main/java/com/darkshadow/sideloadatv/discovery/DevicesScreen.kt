package com.darkshadow.sideloadatv.discovery

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.darkshadow.sideloadatv.auth.AppleIdentity
import com.darkshadow.sideloadatv.ui.ChipTone
import com.darkshadow.sideloadatv.ui.EmptyState
import com.darkshadow.sideloadatv.ui.SectionHeader
import com.darkshadow.sideloadatv.ui.StatusChip

private const val REQUIRED_PERMISSION = Manifest.permission.NEARBY_WIFI_DEVICES

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DevicesScreen(
    discovery: MdnsDiscovery,
    identity: AppleIdentity?,
    onOpenAccount: () -> Unit,
    onOpenDevice: (DiscoveredDevice) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, REQUIRED_PERMISSION) == PackageManager.PERMISSION_GRANTED,
        )
    }
    var isDiscovering by remember { mutableStateOf(false) }
    val devices by discovery.devices.collectAsState()

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        hasPermission = granted
        if (granted) {
            discovery.start()
            isDiscovering = true
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = { TopAppBar(title = { Text("sideloadATV") }) },
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(innerPadding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 16.dp),
        ) {
            item { AccountCard(identity = identity, onClick = onOpenAccount) }

            item {
                DiscoveryControl(
                    hasPermission = hasPermission,
                    isDiscovering = isDiscovering,
                    onRequestPermission = { permissionLauncher.launch(REQUIRED_PERMISSION) },
                    onToggle = {
                        if (isDiscovering) discovery.stop() else discovery.start()
                        isDiscovering = !isDiscovering
                    },
                )
            }

            item { SectionHeader("Apple TVs (${devices.size})") }

            if (devices.isEmpty()) {
                item {
                    EmptyState(
                        icon = Icons.Filled.Search,
                        title = if (isDiscovering) "Scanning…" else "No devices yet",
                        subtitle = if (isDiscovering) {
                            "Make sure your Apple TV is powered on and on the same Wi-Fi network."
                        } else {
                            "Start discovery to find Apple TVs on your network."
                        },
                    )
                }
            } else {
                items(devices, key = { it.serviceName }) { device ->
                    DeviceCard(device = device, onClick = { onOpenDevice(device) })
                }
            }
        }
    }
}

@Composable
private fun AccountCard(identity: AppleIdentity?, onClick: () -> Unit) {
    val title = when (identity) {
        null -> "Not signed in"
        is AppleIdentity.Live -> "Apple ID account"
        is AppleIdentity.Restored -> identity.account.firstName
    }
    val subtitle = when (identity) {
        null -> "Tap to log in with your Apple ID"
        else -> "Signed in — tap to manage"
    }
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = Icons.Filled.AccountCircle,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.size(40.dp),
            )
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                )
            }
            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSecondaryContainer,
            )
        }
    }
}

@Composable
private fun DiscoveryControl(
    hasPermission: Boolean,
    isDiscovering: Boolean,
    onRequestPermission: () -> Unit,
    onToggle: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (!hasPermission) {
            Button(onClick = onRequestPermission, modifier = Modifier.fillMaxWidth()) {
                Text("Grant nearby-devices permission")
            }
            Text(
                text = "Needed to discover Apple TVs over Wi-Fi (mDNS).",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else if (isDiscovering) {
            OutlinedButton(onClick = onToggle, modifier = Modifier.fillMaxWidth()) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.width(12.dp))
                Text("Scanning — tap to stop")
            }
        } else {
            Button(
                onClick = onToggle,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(),
            ) {
                Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Start discovery")
            }
        }
    }
}

@Composable
private fun DeviceCard(device: DiscoveredDevice, onClick: () -> Unit) {
    val ready = device.verified.isUsable
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = device.serviceName,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                StatusChip(
                    text = if (ready) "Ready to connect" else "Pairing required",
                    tone = if (ready) ChipTone.Success else ChipTone.Neutral,
                )
            }
            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
