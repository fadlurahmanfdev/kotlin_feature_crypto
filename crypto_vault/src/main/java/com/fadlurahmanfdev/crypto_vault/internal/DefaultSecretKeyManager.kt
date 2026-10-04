package com.fadlurahmanfdev.crypto_vault.internal

import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.internal.contracts.SecretKeyManager
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

internal class DefaultSecretKeyManager: SecretKeyManager {
    override fun generate(algorithm: String, keySize: Int): SecretKey {
        return try {
            val keyGenerator = KeyGenerator.getInstance(algorithm)
            keyGenerator.init(keySize)
            keyGenerator.generateKey()
        } catch (e: Exception) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to generate AES key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun parse(key: ByteArray, algorithm: String): SecretKey {
        return SecretKeySpec(key, algorithm)
    }
}