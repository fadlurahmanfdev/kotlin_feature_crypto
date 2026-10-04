package com.fadlurahmanfdev.crypto_vault.api

import com.fadlurahmanfdev.crypto_vault.internal.DefaultSecretKeyManager
import com.fadlurahmanfdev.crypto_vault.internal.contracts.SecretKeyManager
import javax.crypto.SecretKey

class CryptoVaultSoftwareSecretKeyManager internal constructor(
    private val secretKeyManager: SecretKeyManager,
) {
    companion object {
        fun create(): CryptoVaultSoftwareSecretKeyManager {
            return CryptoVaultSoftwareSecretKeyManager(
                secretKeyManager = DefaultSecretKeyManager()
            )
        }
    }

    fun generateKey(algorithm: String, keySize: Int = 256): SecretKey = secretKeyManager.generate(algorithm = algorithm, keySize = keySize)
}