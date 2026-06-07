package com.fadlurahmanfdev.crypto_vault.api

import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.internal.base.BaseKeyCryptoVault
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultEncryptedModel
import java.security.spec.AlgorithmParameterSpec

/**
 * Generic symmetric crypto vault for algorithms such as AES, ChaCha20, DES, and 3DES.
 *
 * Extend this class to customize transformation handling for your application.
 */
open class CryptoVaultCustomKeyVault : BaseKeyCryptoVault() {
    /** Generates a software key for the given [algorithm] encoded as Base64. */
    override fun generateKey(algorithm: CryptoVaultAlgorithm): String = super.generateKey(algorithm)

    /** Encrypts [plainText] with a custom [transformation] and [algorithmParameterSpec]. */
    override fun encrypt(
        algorithm: CryptoVaultAlgorithm,
        encodedSecretKey: String,
        transformation: String,
        plainText: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): String = super.encrypt(
        algorithm = algorithm,
        encodedSecretKey = encodedSecretKey,
        transformation = transformation,
        plainText = plainText,
        algorithmParameterSpec = algorithmParameterSpec,
    )

    /** Encrypts [plainText] and returns ciphertext with a cipher-generated IV. */
    override fun encrypt(
        algorithm: CryptoVaultAlgorithm,
        encodedSecretKey: String,
        transformation: String,
        plainText: String,
    ): CryptoVaultEncryptedModel = super.encrypt(
        algorithm = algorithm,
        encodedSecretKey = encodedSecretKey,
        transformation = transformation,
        plainText = plainText,
    )

    /** Decrypts [encryptedText] with a custom [transformation] and [algorithmParameterSpec]. */
    override fun decrypt(
        algorithm: CryptoVaultAlgorithm,
        encodedSecretKey: String,
        transformation: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encryptedText: String,
    ): String = super.decrypt(
        algorithm = algorithm,
        transformation = transformation,
        encodedSecretKey = encodedSecretKey,
        algorithmParameterSpec = algorithmParameterSpec,
        encryptedText = encryptedText,
    )
}
