package com.fadlurahmanfdev.crypto_vault.api

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.domain.contracts.SecretKeyManager
import com.fadlurahmanfdev.crypto_vault.internal.DefaultSecretKeyManager
import javax.crypto.SecretKey

class CryptoVaultSecretKeyManager internal constructor(
    private val secretKeyManager: SecretKeyManager,
) {
    companion object {
        fun create(): CryptoVaultSecretKeyManager {
            return CryptoVaultSecretKeyManager(
                secretKeyManager = DefaultSecretKeyManager.create()
            )
        }
    }

    @RequiresApi(Build.VERSION_CODES.P)
    fun isSupportStrongBox(context: Context): Boolean = secretKeyManager.isSupportStrongBox(context)

    fun getKey(keyStoreAlias: String): SecretKey = secretKeyManager.getKey(keyStoreAlias)

    fun isKeyExist(keyStoreAlias: String): Boolean = secretKeyManager.isKeyExist(keyStoreAlias)

    fun deleteKey(keyStoreAlias: String) = secretKeyManager.deleteKey(keyStoreAlias)
}