package com.darkshadow.sideloadatv.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.util.Log
import java.net.InetAddress
import java.util.concurrent.Executors
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

private const val TAG = "MdnsDiscovery"

/**
 * PIN/SRP pair-setup only. Once paired, `createListener` requests sent over
 * *this* service are rejected by the device with "Tunnel listener creator
 * not set" -- the tunnel step needs [VERIFIED_PAIRING_SERVICE_TYPE] instead.
 */
const val MANUAL_PAIRING_SERVICE_TYPE = "_remotepairing-manual-pairing._tcp"

/**
 * Advertised only after a host has successfully paired. The post-pairing
 * tunnel (`RemotePairingClient::create_tcp_listener`) must connect here, not
 * to the manual-pairing service.
 */
const val VERIFIED_PAIRING_SERVICE_TYPE = "_remotepairing._tcp"

private val SERVICE_TYPES = listOf(MANUAL_PAIRING_SERVICE_TYPE, VERIFIED_PAIRING_SERVICE_TYPE)

data class Endpoint(
    val addresses: List<InetAddress> = emptyList(),
    val port: Int = -1,
) {
    val isUsable: Boolean get() = addresses.isNotEmpty() && port > 0
}

data class DiscoveredDevice(
    /** Display name -- the manual-pairing service's human-readable name (e.g. "Living Room"). */
    val serviceName: String,
    /** Endpoint for [MANUAL_PAIRING_SERVICE_TYPE] -- used by `PairingSession.pair`. */
    val manualPairing: Endpoint = Endpoint(),
    /** Endpoint for [VERIFIED_PAIRING_SERVICE_TYPE] -- used by `TunnelSession.connect`. */
    val verified: Endpoint = Endpoint(),
    /** Raw mDNS instance names backing each endpoint, needed to match `onServiceLost` back to this device. */
    val manualRawName: String? = null,
    val verifiedRawName: String? = null,
)

private fun addressesOverlap(a: List<InetAddress>, b: List<InetAddress>): Boolean =
    a.any { x -> b.any { y -> x.hostAddress == y.hostAddress } }

class MdnsDiscovery(context: Context) {
    private val appContext = context.applicationContext
    private val nsdManager = appContext.getSystemService(NsdManager::class.java)
    private val wifiManager = appContext.getSystemService(WifiManager::class.java)
    private val callbackExecutor = Executors.newSingleThreadExecutor()

    private var multicastLock: WifiManager.MulticastLock? = null
    private val discoveryListeners = mutableMapOf<String, NsdManager.DiscoveryListener>()
    private val serviceInfoCallbacks = mutableMapOf<String, NsdManager.ServiceInfoCallback>()

    private val _devices = MutableStateFlow<List<DiscoveredDevice>>(emptyList())
    val devices: StateFlow<List<DiscoveredDevice>> = _devices

    private val _events = MutableStateFlow<List<String>>(emptyList())
    val events: StateFlow<List<String>> = _events

    fun start() {
        acquireMulticastLock()
        _devices.value = emptyList()
        SERVICE_TYPES.forEach { serviceType -> startDiscoveryFor(serviceType) }
    }

    fun stop() {
        discoveryListeners.forEach { (serviceType, listener) ->
            runCatching { nsdManager.stopServiceDiscovery(listener) }
                .onFailure { log("stopServiceDiscovery threw for $serviceType: ${it.message}") }
        }
        discoveryListeners.clear()
        serviceInfoCallbacks.keys.toList().forEach { unregisterInfoCallback(it) }
        releaseMulticastLock()
    }

    private fun startDiscoveryFor(serviceType: String) {
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {
                log("Discovery started for $serviceType")
            }

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                log("Service found ($serviceType): ${serviceInfo.serviceName}")
                registerInfoCallback(serviceType, serviceInfo)
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                log("Service lost ($serviceType): ${serviceInfo.serviceName}")
                unregisterInfoCallback(callbackKey(serviceType, serviceInfo.serviceName))
                _devices.update { list ->
                    list.map { device ->
                        if (serviceType == MANUAL_PAIRING_SERVICE_TYPE && device.manualRawName == serviceInfo.serviceName) {
                            device.copy(manualPairing = Endpoint(), manualRawName = null)
                        } else if (serviceType == VERIFIED_PAIRING_SERVICE_TYPE && device.verifiedRawName == serviceInfo.serviceName) {
                            device.copy(verified = Endpoint(), verifiedRawName = null)
                        } else {
                            device
                        }
                    }
                }
            }

            override fun onDiscoveryStopped(regType: String) {
                log("Discovery stopped for $serviceType")
            }

            override fun onStartDiscoveryFailed(regType: String, errorCode: Int) {
                log("Start discovery failed for $serviceType: error=$errorCode")
            }

            override fun onStopDiscoveryFailed(regType: String, errorCode: Int) {
                log("Stop discovery failed for $serviceType: error=$errorCode")
            }
        }
        discoveryListeners[serviceType] = listener
        runCatching {
            nsdManager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
        }.onFailure { log("discoverServices threw for $serviceType: ${it.message}") }
    }

    private fun callbackKey(serviceType: String, serviceName: String) = "$serviceType|$serviceName"

    private fun registerInfoCallback(serviceType: String, serviceInfo: NsdServiceInfo) {
        val key = callbackKey(serviceType, serviceInfo.serviceName)
        val callback = object : NsdManager.ServiceInfoCallback {
            override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) {
                log("Resolve registration failed for ${serviceInfo.serviceName} ($serviceType): $errorCode")
            }

            override fun onServiceUpdated(updated: NsdServiceInfo) {
                log("Resolved ${updated.serviceName} ($serviceType) -> ${updated.hostAddresses}:${updated.port}")
                val endpoint = Endpoint(addresses = updated.hostAddresses, port = updated.port)
                _devices.update { list ->
                    // The manual-pairing and verified services advertise under unrelated
                    // instance names (the latter uses a UDID-style name, not "Living Room"),
                    // so the only reliable way to tell they're the same physical Apple TV is
                    // that they resolve to overlapping IP addresses.
                    val matchIndex = list.indexOfFirst { device ->
                        device.manualRawName == updated.serviceName ||
                            device.verifiedRawName == updated.serviceName ||
                            addressesOverlap(device.manualPairing.addresses, endpoint.addresses) ||
                            addressesOverlap(device.verified.addresses, endpoint.addresses)
                    }
                    val base = if (matchIndex >= 0) list[matchIndex] else DiscoveredDevice(updated.serviceName)
                    val merged = if (serviceType == MANUAL_PAIRING_SERVICE_TYPE) {
                        base.copy(serviceName = updated.serviceName, manualPairing = endpoint, manualRawName = updated.serviceName)
                    } else {
                        base.copy(verified = endpoint, verifiedRawName = updated.serviceName)
                    }
                    if (matchIndex >= 0) list.toMutableList().apply { set(matchIndex, merged) } else list + merged
                }
            }

            override fun onServiceLost() {
                log("Resolved service lost: ${serviceInfo.serviceName} ($serviceType)")
            }

            override fun onServiceInfoCallbackUnregistered() {
                log("Resolve callback unregistered for ${serviceInfo.serviceName} ($serviceType)")
            }
        }
        serviceInfoCallbacks[key] = callback
        runCatching {
            nsdManager.registerServiceInfoCallback(serviceInfo, callbackExecutor, callback)
        }.onFailure { log("registerServiceInfoCallback threw for $key: ${it.message}") }
    }

    private fun unregisterInfoCallback(key: String) {
        serviceInfoCallbacks.remove(key)?.let { callback ->
            runCatching { nsdManager.unregisterServiceInfoCallback(callback) }
        }
    }

    private fun acquireMulticastLock() {
        if (multicastLock?.isHeld == true) return
        multicastLock = wifiManager.createMulticastLock("sideloadatv-mdns").apply {
            setReferenceCounted(true)
            acquire()
        }
        log("Multicast lock acquired")
    }

    private fun releaseMulticastLock() {
        multicastLock?.let { if (it.isHeld) it.release() }
        multicastLock = null
        log("Multicast lock released")
    }

    private fun log(message: String) {
        Log.d(TAG, message)
        _events.update { it + message }
    }
}
