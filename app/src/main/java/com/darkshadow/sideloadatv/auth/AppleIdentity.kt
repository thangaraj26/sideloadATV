package com.darkshadow.sideloadatv.auth

import uniffi.sideloadatv_ffi.GrandslamSession
import uniffi.sideloadatv_ffi.SigningSession
import uniffi.sideloadatv_ffi.StoredAccount

/// However the user got signed in this run -- either a fresh SRP login
/// (`Live`, backed by a real `GrandslamSession`) or a restored session from a
/// previous launch (`Restored`, backed only by the durable `adsid` +
/// `xcode_gs_token` pair -- see `GrandslamSession.exportAccount`). Both can
/// build a `SigningSession` for installing/refreshing apps; only `Live` can
/// do things that need the full GrandSlam session, like re-pairing 2FA flows.
sealed class AppleIdentity {
    data class Live(val session: GrandslamSession) : AppleIdentity()
    data class Restored(val account: StoredAccount) : AppleIdentity()

    suspend fun buildSigningSession(dataDir: String): SigningSession = when (this) {
        is Live -> SigningSession.create(session)
        is Restored -> SigningSession.fromStored(dataDir, account.adsid, account.xcodeGsToken)
    }
}
