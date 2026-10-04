package com.fadlurahmanfdev.crypto_vault.api

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.internal.contracts.KeyStoreSecretKeyManager
import com.fadlurahmanfdev.crypto_vault.internal.AndroidKeyStoreSecretKeyManager
import java.security.cert.Certificate
import javax.crypto.SecretKey

class CryptoVaultAndroidKeyStoreSecretKeyManager internal constructor(
    private val secretKeyManager: KeyStoreSecretKeyManager,
) {
    companion object {
        fun create(): CryptoVaultAndroidKeyStoreSecretKeyManager {
            return CryptoVaultAndroidKeyStoreSecretKeyManager(
                secretKeyManager = AndroidKeyStoreSecretKeyManager()
            )
        }
    }

    @RequiresApi(Build.VERSION_CODES.P)
    fun isSupportStrongBox(context: Context): Boolean = secretKeyManager.isSupportStrongBox(context = context)

    fun generateKey(
        keyStoreAlias: String,
        keySize: Int,
        blockMode: String,
        padding: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit,
    ): SecretKey = secretKeyManager.generateKey(
        keyStoreAlias = keyStoreAlias,
        keySize = keySize,
        blockMode = blockMode,
        padding = padding,
        strongBoxBacked = strongBoxBacked,
        keyGenParameterSpecBuilder = keyGenParameterSpecBuilder
    )
    fun getKey(keyStoreAlias: String): SecretKey? = secretKeyManager.getKey(keyStoreAlias)

    fun isKeyExist(keyStoreAlias: String): Boolean = secretKeyManager.isKeyExist(keyStoreAlias)

    fun deleteKey(keyStoreAlias: String) = secretKeyManager.deleteKey(keyStoreAlias)

    fun getCertificateAlias(certificate: Certificate): String = secretKeyManager.getCertificateAlias(certificate)

    fun getCertificate(keyStoreAlias: String): Certificate = secretKeyManager.getCertificate(keyStoreAlias)

    fun getCertificateChain(keyStoreAlias: String): Array<Certificate> = secretKeyManager.getCertificateChain(keyStoreAlias)
}