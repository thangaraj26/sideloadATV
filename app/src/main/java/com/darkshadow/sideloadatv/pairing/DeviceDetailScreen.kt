package com.darkshadow.sideloadatv.pairing

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.darkshadow.sideloadatv.auth.AppleIdentity
import com.darkshadow.sideloadatv.discovery.DiscoveredDevice
import com.darkshadow.sideloadatv.ui.ChipTone
import com.darkshadow.sideloadatv.ui.SectionHeader
import com.darkshadow.sideloadatv.ui.StatusChip
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import uniffi.sideloadatv_ffi.AppIdInfo
import uniffi.sideloadatv_ffi.InstallProgressListener
import uniffi.sideloadatv_ffi.InstalledApp
import uniffi.sideloadatv_ffi.PairingResult
import uniffi.sideloadatv_ffi.PairingSession
import uniffi.sideloadatv_ffi.PinPrompter
import uniffi.sideloadatv_ffi.SigningException
import uniffi.sideloadatv_ffi.SigningSession
import uniffi.sideloadatv_ffi.StoredAppInfo
import uniffi.sideloadatv_ffi.TunnelSession
import uniffi.sideloadatv_ffi.listStoredApps
import uniffi.sideloadatv_ffi.refreshStoredApp

private const val SENDING_HOST = "sideloadATV"

private fun pairingFileFor(context: Context, device: DiscoveredDevice): File {
    val safeName = device.serviceName.replace(Regex("[^A-Za-z0-9._-]"), "_")
    return File(context.filesDir, "pairing_$safeName.plist")
}

private fun displayNameFor(context: Context, uri: Uri): String? {
    return context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
        val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
    }
}

/// An installed app enriched with our local record of when its provisioning
/// profile expires, if we're the one that signed it. `remainingDays` is null
/// for apps we have no local record of (installed some other way, or the
/// record was lost) -- there's no on-device API for provisioning profile
/// expiry, so those just show as "unknown".
private data class AppRow(
    val installed: InstalledApp,
    val stored: StoredAppInfo?,
) {
    val remainingDays: Long?
        get() = stored?.let {
            TimeUnit.SECONDS.toDays(it.expiresAt - System.currentTimeMillis() / 1000)
        }
}

private data class AppIdSwapState(
    val signing: SigningSession,
    val teamId: String,
    val appIds: List<AppIdInfo>,
    val ipaPath: String,
    val fileName: String,
)

private data class ManageAppIdsState(
    val signing: SigningSession,
    val teamId: String,
    val appIds: List<AppIdInfo>,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceDetailScreen(
    device: DiscoveredDevice,
    identity: AppleIdentity?,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val pairingFile = remember(device.serviceName) { pairingFileFor(context, device) }

    var status by remember(device.serviceName) { mutableStateOf<String?>(null) }
    var isBusy by remember(device.serviceName) { mutableStateOf(false) }
    var pinRequest by remember(device.serviceName) { mutableStateOf<CompletableDeferred<String>?>(null) }
    var pinInput by remember(device.serviceName) { mutableStateOf("") }
    var hasPairing by remember(device.serviceName) { mutableStateOf(pairingFile.exists()) }
    var tunnelSession by remember(device.serviceName) { mutableStateOf<TunnelSession?>(null) }
    var appRows by remember(device.serviceName) { mutableStateOf<List<AppRow>?>(null) }
    var installProgress by remember(device.serviceName) { mutableStateOf<Int?>(null) }
    var appIdSwap by remember(device.serviceName) { mutableStateOf<AppIdSwapState?>(null) }
    var appIdSwapSelected by remember(device.serviceName) { mutableStateOf<String?>(null) }
    var manageAppIds by remember(device.serviceName) { mutableStateOf<ManageAppIdsState?>(null) }
    var deletingAppId by remember(device.serviceName) { mutableStateOf<String?>(null) }

    val canPair = !isBusy && device.manualPairing.isUsable
    val canTunnel = !isBusy && device.verified.isUsable

    suspend fun refreshAppRows(session: TunnelSession) {
        val installed = runCatching { session.listInstalledApps() }.getOrElse {
            status = "List apps failed: ${it.message}"
            return
        }
        val stored = runCatching { listStoredApps(context.filesDir.absolutePath) }.getOrDefault(emptyList())
            .associateBy { it.bundleIdentifier }
        appRows = installed.map { app -> AppRow(app, stored[app.bundleIdentifier]) }
        status = "${installed.size} apps installed"
    }

    fun installSignedIpa(session: TunnelSession, signing: suspend () -> String, fileName: String) {
        isBusy = true
        installProgress = 0
        scope.launch(Dispatchers.IO) {
            runCatching {
                val signedPath = signing()
                status = "Uploading & installing $fileName..."
                val listener = object : InstallProgressListener {
                    override suspend fun onProgress(percentComplete: UInt) {
                        installProgress = percentComplete.toInt()
                    }
                }
                session.installIpa(signedPath, fileName, listener)
            }.onSuccess {
                status = "Install complete"
                refreshAppRows(session)
            }.onFailure { error ->
                status = "Install failed: ${error.message}"
            }
            installProgress = null
            isBusy = false
        }
    }

    val ipaPickerLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        val session = tunnelSession
        val signInIdentity = identity
        if (uri == null || session == null || signInIdentity == null) return@rememberLauncherForActivityResult

        isBusy = true
        installProgress = 0
        scope.launch(Dispatchers.IO) {
            var signingSession: SigningSession? = null
            var teamId: String? = null
            var tempInputFile: File? = null
            var fileName: String? = null
            try {
                // Stream the picked file to a temp file — never read the whole
                // IPA into JVM heap (an 850 MB app would OOM immediately).
                fileName = displayNameFor(context, uri) ?: "app.ipa"
                tempInputFile = File(context.cacheDir, "sideloadatv-input-${UUID.randomUUID()}.ipa")
                status = "Copying $fileName..."
                context.contentResolver.openInputStream(uri)?.use { input ->
                    tempInputFile.outputStream().use { output -> input.copyTo(output) }
                } ?: error("could not open picked file")

                status = "Requesting Apple Developer session..."
                signingSession = signInIdentity.buildSigningSession(context.filesDir.absolutePath)
                status = "Looking up Apple Developer team..."
                val team = signingSession.listTeams().firstOrNull()
                    ?: error("no Apple Developer team available for this Apple ID")
                teamId = team.id
                status = "Signing $fileName for ${device.serviceName} (team ${team.name})..."
                val signedPath = signingSession.signIpa(
                    tempInputFile.absolutePath,
                    teamId,
                    session.info().deviceUuid,
                    device.serviceName,
                    context.filesDir.absolutePath,
                    context.cacheDir.absolutePath,
                )
                status = "Uploading & installing $fileName..."
                val listener = object : InstallProgressListener {
                    override suspend fun onProgress(percentComplete: UInt) {
                        installProgress = percentComplete.toInt()
                    }
                }
                // install_ipa deletes the signed file after upload
                session.installIpa(signedPath, fileName, listener)
                status = "Install complete"
                refreshAppRows(session)
            } catch (e: SigningException.AppIdLimitReached) {
                val s = signingSession
                val t = teamId
                val p = tempInputFile?.absolutePath
                if (s != null && t != null && p != null) {
                    appIdSwap = AppIdSwapState(s, t, e.existingAppIds, p, fileName ?: "app.ipa")
                    appIdSwapSelected = e.existingAppIds.firstOrNull()?.id
                    tempInputFile = null // ownership transferred to AppIdSwapState
                } else {
                    status = "Install failed: ${e.message}"
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                status = "Install failed: ${e.message}"
            } finally {
                tempInputFile?.delete()
            }
            installProgress = null
            isBusy = false
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Text(device.serviceName, maxLines = 1, overflow = TextOverflow.Ellipsis)
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // --- Step 1: pairing --------------------------------------------
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    StepHeader(
                        title = "1  ·  Pairing",
                        chipText = if (hasPairing) "Paired" else "Not paired",
                        chipTone = if (hasPairing) ChipTone.Success else ChipTone.Neutral,
                    )
                    Button(
                        enabled = canPair,
                        modifier = Modifier.fillMaxWidth(),
                        onClick = {
                            val address = device.manualPairing.addresses.first()
                            val port = device.manualPairing.port
                            isBusy = true
                            status = "Connecting..."
                            scope.launch(Dispatchers.IO) {
                                val existing = if (pairingFile.exists()) pairingFile.readBytes() else null
                                val prompter = object : PinPrompter {
                                    override suspend fun requestPin(): String {
                                        val deferred = CompletableDeferred<String>()
                                        pinRequest = deferred
                                        return deferred.await()
                                    }
                                }
                                runCatching {
                                    PairingSession().pair(
                                        address.hostAddress ?: address.toString(),
                                        port.toUShort(),
                                        SENDING_HOST,
                                        existing,
                                        prompter,
                                    )
                                }.onSuccess { result: PairingResult ->
                                    pairingFile.writeBytes(result.pairingFile)
                                    hasPairing = true
                                    status = "Paired" + (result.deviceName?.let { " with $it" } ?: " (existing pairing reused)")
                                }.onFailure { error ->
                                    status = "Pairing failed: ${error.message}"
                                }
                                pinRequest = null
                                isBusy = false
                            }
                        },
                    ) { Text(if (hasPairing) "Re-pair" else "Pair") }
                    if (!device.manualPairing.isUsable) {
                        HintText("Waiting for _remotepairing-manual-pairing._tcp on this device…")
                    }
                }
            }

            // --- Step 2: connection -----------------------------------------
            if (hasPairing) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        StepHeader(
                            title = "2  ·  Connection",
                            chipText = if (tunnelSession != null) "Connected" else "Not connected",
                            chipTone = if (tunnelSession != null) ChipTone.Success else ChipTone.Neutral,
                        )
                        Button(
                            enabled = canTunnel,
                            modifier = Modifier.fillMaxWidth(),
                            onClick = {
                                val address = device.verified.addresses.first()
                                val port = device.verified.port
                                isBusy = true
                                status = "Opening tunnel..."
                                appRows = null
                                scope.launch(Dispatchers.IO) {
                                    runCatching {
                                        TunnelSession.connect(
                                            address.hostAddress ?: address.toString(),
                                            port.toUShort(),
                                            SENDING_HOST,
                                            pairingFile.readBytes(),
                                        )
                                    }.onSuccess { session ->
                                        tunnelSession = session
                                        status = "Tunnel up"
                                        refreshAppRows(session)
                                    }.onFailure { error ->
                                        tunnelSession = null
                                        status = "Tunnel failed: ${error.message}"
                                    }
                                    isBusy = false
                                }
                            },
                        ) { Text(if (tunnelSession != null) "Reconnect" else "Connect") }
                        tunnelSession?.let { HintText("Device UDID: ${it.info().deviceUuid}") }
                        if (!device.verified.isUsable) {
                            HintText("Waiting for _remotepairing._tcp (verified service)…")
                        }
                    }
                }
            }

            // --- Step 3: installed apps -------------------------------------
            tunnelSession?.let { session ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    SectionHeader("Installed apps")
                    IconButton(enabled = !isBusy, onClick = { scope.launch(Dispatchers.IO) { refreshAppRows(session) } }) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Refresh list")
                    }
                }

                appRows?.forEach { row ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = row.installed.name,
                                style = MaterialTheme.typography.titleMedium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = row.installed.bundleIdentifier,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            val (label, tone) = expiryChip(row.remainingDays)
                            StatusChip(text = label, tone = tone)
                            if (row.stored != null && identity != null) {
                                FilledTonalButton(
                                    enabled = !isBusy,
                                    modifier = Modifier.fillMaxWidth(),
                                    onClick = {
                                        val signInIdentity = identity
                                        installSignedIpa(
                                            session,
                                            signing = {
                                                val signing = signInIdentity.buildSigningSession(context.filesDir.absolutePath)
                                                refreshStoredApp(
                                                    signing,
                                                    context.filesDir.absolutePath,
                                                    context.cacheDir.absolutePath,
                                                    row.stored.bundleIdentifier,
                                                ) // returns signed path; install_ipa deletes it
                                            },
                                            fileName = row.stored.fileName,
                                        )
                                    },
                                ) {
                                    Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(8.dp))
                                    Text("Refresh — resets 7-day limit")
                                }
                            }
                            FilledTonalButton(
                                enabled = !isBusy,
                                modifier = Modifier.fillMaxWidth(),
                                onClick = {
                                    isBusy = true
                                    val bundleId = row.installed.bundleIdentifier
                                    scope.launch(Dispatchers.IO) {
                                        status = "Enabling JIT for ${row.installed.name}…"
                                        runCatching { session.enableJit(bundleId) }
                                            .onSuccess { status = "JIT enabled for ${row.installed.name}" }
                                            .onFailure { status = "Enable JIT failed: ${it.message}" }
                                        isBusy = false
                                    }
                                },
                            ) {
                                Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text("Enable JIT")
                            }
                        }
                    }
                }

                Button(
                    enabled = !isBusy && identity != null,
                    modifier = Modifier.fillMaxWidth(),
                    onClick = { ipaPickerLauncher.launch(arrayOf("*/*")) },
                ) {
                    Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Install new IPA…")
                }
                if (identity != null) {
                    OutlinedButton(
                        enabled = !isBusy,
                        modifier = Modifier.fillMaxWidth(),
                        onClick = {
                            isBusy = true
                            scope.launch(Dispatchers.IO) {
                                try {
                                    status = "Loading App IDs…"
                                    val signing = identity.buildSigningSession(context.filesDir.absolutePath)
                                    val team = signing.listTeams().firstOrNull()
                                        ?: error("No developer team found for this Apple ID")
                                    val appIds = signing.listRegisteredAppIds(team.id)
                                    manageAppIds = ManageAppIdsState(signing, team.id, appIds)
                                    status = null
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: Exception) {
                                    status = "Failed to load App IDs: ${e.message}"
                                }
                                isBusy = false
                            }
                        },
                    ) {
                        Text("Manage App IDs…")
                    }
                } else {
                    HintText("Log in with your Apple ID (Account) to sign and install apps.")
                }
            }

            // --- Progress + status ------------------------------------------
            installProgress?.let { percent ->
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    LinearProgressIndicator(
                        progress = { percent / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(
                        text = "$percent%",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            status?.let { StatusBanner(it, busy = isBusy && installProgress == null) }
        }
    }

    manageAppIds?.let { state ->
        var currentIds by remember(state) { mutableStateOf(state.appIds) }
        AlertDialog(
            onDismissRequest = { if (deletingAppId == null) manageAppIds = null },
            title = { Text("Registered App IDs") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                    Text(
                        "Free accounts: up to 10 App IDs per 7 days. Delete slots you no longer need.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.size(8.dp))
                    if (currentIds.isEmpty()) {
                        Text(
                            "No registered App IDs.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        currentIds.forEachIndexed { index, appId ->
                            if (index > 0) HorizontalDivider()
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        appId.name,
                                        style = MaterialTheme.typography.bodyMedium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Text(
                                        appId.identifier,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                                Spacer(Modifier.width(8.dp))
                                if (deletingAppId == appId.id) {
                                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                                } else {
                                    TextButton(
                                        enabled = deletingAppId == null,
                                        onClick = {
                                            deletingAppId = appId.id
                                            scope.launch(Dispatchers.IO) {
                                                try {
                                                    state.signing.deleteRegisteredAppId(state.teamId, appId.id)
                                                    currentIds = currentIds.filter { it.id != appId.id }
                                                } catch (e: CancellationException) {
                                                    throw e
                                                } catch (e: Exception) {
                                                    status = "Delete failed: ${e.message}"
                                                }
                                                deletingAppId = null
                                            }
                                        },
                                    ) { Text("Delete") }
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(
                    enabled = deletingAppId == null,
                    onClick = { manageAppIds = null },
                ) { Text("Done") }
            },
        )
    }

    appIdSwap?.let { swap ->
        var selected by remember(swap) { mutableStateOf(appIdSwapSelected ?: swap.appIds.firstOrNull()?.id) }
        AlertDialog(
            onDismissRequest = { appIdSwap = null },
            title = { Text("3-App Limit Reached") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        "Free Apple IDs support 3 apps. Remove one slot to install a new app " +
                            "(the app stays on your Apple TV — only its signing slot is freed):",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    swap.appIds.forEach { appId ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            RadioButton(
                                selected = selected == appId.id,
                                onClick = { selected = appId.id },
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(appId.name, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(appId.identifier, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = selected != null,
                    onClick = {
                        val selectedId = selected ?: return@TextButton
                        val savedSwap = swap
                        val session = tunnelSession ?: return@TextButton
                        appIdSwap = null
                        isBusy = true
                        installProgress = 0
                        scope.launch(Dispatchers.IO) {
                            try {
                                status = "Removing app slot..."
                                savedSwap.signing.deleteRegisteredAppId(savedSwap.teamId, selectedId)
                                status = "Signing ${savedSwap.fileName}..."
                                val signedPath = savedSwap.signing.signIpa(
                                    savedSwap.ipaPath,
                                    savedSwap.teamId,
                                    session.info().deviceUuid,
                                    device.serviceName,
                                    context.filesDir.absolutePath,
                                    context.cacheDir.absolutePath,
                                )
                                File(savedSwap.ipaPath).delete()
                                status = "Uploading & installing ${savedSwap.fileName}..."
                                val listener = object : InstallProgressListener {
                                    override suspend fun onProgress(percentComplete: UInt) {
                                        installProgress = percentComplete.toInt()
                                    }
                                }
                                // install_ipa deletes the signed file after upload
                                session.installIpa(signedPath, savedSwap.fileName, listener)
                                status = "Install complete"
                                refreshAppRows(session)
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                status = "Install failed: ${e.message}"
                            }
                            installProgress = null
                            isBusy = false
                        }
                    },
                ) { Text("Remove & Install") }
            },
            dismissButton = {
                TextButton(onClick = { appIdSwap = null }) { Text("Cancel") }
            },
        )
    }

    pinRequest?.let { request ->
        AlertDialog(
            onDismissRequest = {},
            title = { Text("Enter PIN") },
            text = {
                OutlinedTextField(
                    value = pinInput,
                    onValueChange = { pinInput = it },
                    label = { Text("PIN shown on the Apple TV") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    request.complete(pinInput)
                    pinInput = ""
                    pinRequest = null
                }) { Text("Submit") }
            },
            dismissButton = {
                TextButton(onClick = {
                    request.completeExceptionally(CancellationException("Pairing cancelled by user"))
                    pinInput = ""
                    pinRequest = null
                }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun StepHeader(title: String, chipText: String, chipTone: ChipTone) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text = title, style = MaterialTheme.typography.titleMedium)
        StatusChip(text = chipText, tone = chipTone)
    }
}

@Composable
private fun HintText(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun StatusBanner(text: String, busy: Boolean) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (busy) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
            }
            Text(
                text = text,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/// Human label + color tone for a provisioning-profile expiry countdown.
/// Free Apple IDs get a 7-day profile, so anything at or under 3 days left is
/// worth flagging (amber) and expired/expiring-today is urgent (red).
private fun expiryChip(remainingDays: Long?): Pair<String, ChipTone> = when {
    remainingDays == null -> "Expiry unknown" to ChipTone.Neutral
    remainingDays < 0 -> "Expired" to ChipTone.Danger
    remainingDays == 0L -> "Expires today" to ChipTone.Danger
    remainingDays <= 3 -> "Expires in $remainingDays day${if (remainingDays == 1L) "" else "s"}" to ChipTone.Warning
    else -> "Expires in $remainingDays days" to ChipTone.Success
}
