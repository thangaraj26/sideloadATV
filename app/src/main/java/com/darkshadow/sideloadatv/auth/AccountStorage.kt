package com.darkshadow.sideloadatv.auth

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File
import org.json.JSONObject
import uniffi.sideloadatv_ffi.StoredAccount

private const val FILE_NAME = "account.enc"

private fun encryptedFile(context: Context): EncryptedFile {
    val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    return EncryptedFile.Builder(
        context,
        File(context.filesDir, FILE_NAME),
        masterKey,
        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
    ).build()
}

/// Persists the Apple ID session's durable tokens (not the password) so
/// login survives app restarts. Overwrites any previously stored account --
/// this app only remembers one Apple ID at a time.
fun saveStoredAccount(context: Context, account: StoredAccount) {
    val file = File(context.filesDir, FILE_NAME)
    if (file.exists()) file.delete() // EncryptedFile refuses to write over an existing file.
    val json = JSONObject().apply {
        put("email", account.email)
        put("firstName", account.firstName)
        put("adsid", account.adsid)
        put("xcodeGsToken", account.xcodeGsToken)
    }
    encryptedFile(context).openFileOutput().use { it.write(json.toString().toByteArray(Charsets.UTF_8)) }
}

fun loadStoredAccount(context: Context): StoredAccount? {
    if (!File(context.filesDir, FILE_NAME).exists()) return null
    return try {
        val bytes = encryptedFile(context).openFileInput().use { it.readBytes() }
        val json = JSONObject(String(bytes, Charsets.UTF_8))
        StoredAccount(
            email = json.getString("email"),
            firstName = json.getString("firstName"),
            adsid = json.getString("adsid"),
            xcodeGsToken = json.getString("xcodeGsToken"),
        )
    } catch (e: Exception) {
        // Corrupt file, wrong Keystore key after a device restore, etc. --
        // treat as "no stored account" and let the caller fall back to login.
        null
    }
}

fun clearStoredAccount(context: Context) {
    File(context.filesDir, FILE_NAME).delete()
}
