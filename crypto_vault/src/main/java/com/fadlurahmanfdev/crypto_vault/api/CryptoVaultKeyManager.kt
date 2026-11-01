package com.fadlurahmanfdev.crypto_vault.api

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.domain.contracts.KeyManager
import com.fadlurahmanfdev.crypto_vault.internal.DefaultKeyManager
import java.security.KeyPair
import javax.crypto.SecretKey

class CryptoVaultKeyManager internal constructor(
    private val keyManager: KeyManager,
) {
    companion object {
        fun create(): CryptoVaultKeyManager {
            return CryptoVaultKeyManager(
                keyManager = DefaultKeyManager.create()
            )
        }
    }

    fun isSupportStrongBox(context: Context): Boolean = keyManager.isSupportStrongBox(context)

    fun getKey(keyStoreAlias: String): SecretKey = keyManager.getSecretKey(keyStoreAlias)

    fun getKeyPair(keyStoreAlias: String): KeyPair = keyManager.getKeyPair(keyStoreAlias)

    fun isKeyExist(keyStoreAlias: String): Boolean = keyManager.isKeyExist(keyStoreAlias)

    fun deleteKey(keyStoreAlias: String) = keyManager.deleteKey(keyStoreAlias)
}