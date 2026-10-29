package com.fadlurahmanfdev.crypto_vault.internal.contracts

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import androidx.annotation.RequiresApi
import java.security.cert.Certificate
import javax.crypto.SecretKey

internal interface KeyStoreSecretKeyManager {
    @RequiresApi(Build.VERSION_CODES.P)
    fun isSupportStrongBox(context: Context): Boolean
    fun generateKey(
        algorithm: String,
        keyStoreAlias: String,
        keySize: Int,
        blockMode: String,
        padding: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit,
    ): SecretKey
    fun getKey(keyStoreAlias: String): SecretKey?
    fun isKeyExist(keyStoreAlias: String): Boolean
    fun deleteKey(keyStoreAlias: String)
    fun getCertificateAlias(certificate: Certificate): String
    fun getCertificate(keyStoreAlias: String): Certificate
    fun getCertificateChain(keyStoreAlias: String): Array<Certificate>
}