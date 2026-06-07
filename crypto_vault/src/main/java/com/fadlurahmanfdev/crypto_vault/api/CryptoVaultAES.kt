package com.fadlurahmanfdev.crypto_vault.api

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESBlockMode
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESEncryptionPadding
import com.fadlurahmanfdev.crypto_vault.internal.base.BaseKeyCryptoVault
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultEncryptedModel
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

/**
 * AES encryption vault backed by Android Keystore or in-memory keys.
 *
 * Use this class when you need AES-GCM/CBC encryption with hardware-backed keys
 * (TEE / StrongBox when available on API 28+).
 */
open class CryptoVaultAES : BaseKeyCryptoVault() {
    private val algorithm = CryptoVaultAlgorithm.AES

    /**
     * Generates an AES key inside Android Keystore.
     *
     * @param keystoreAlias Key identifier stored in Android Keystore.
     * @param strongBoxBacked Request StrongBox backing on API 28+.
     * @param blockMode AES block mode.
     * @param encryptionPadding AES padding mode.
     * @param randomizedEncryptionRequired When true, the cipher must generate its own IV.
     *        Set to false only when you need to supply a custom IV during encryption.
     * @throws com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException when key generation fails.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    open fun generateKeyFromAndroidKeyStore(
        keystoreAlias: String,
        strongBoxBacked: Boolean,
        blockMode: CryptoVaultAESBlockMode,
        encryptionPadding: CryptoVaultAESEncryptionPadding,
        randomizedEncryptionRequired: Boolean = true,
    ): SecretKey {
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).apply {
            setBlockModes(blockMode.value)
            setEncryptionPaddings(encryptionPadding.value)
            setKeySize(256)
            setRandomizedEncryptionRequired(randomizedEncryptionRequired)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(strongBoxBacked)
            }
        }.build()
        return generateKeyFromAndroidKeyStore(
            algorithm = CryptoVaultAlgorithm.AES,
            keyGenParameterSpec = keyGenParameterSpec,
        )
    }

    /** Generates a software AES key encoded as Base64. */
    open fun generateKey(): String = generateKey(CryptoVaultAlgorithm.AES)

    /** Generates a Base64-encoded 16-byte IV for CBC mode. */
    open fun generateIVParameterSpecKey(): String {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(16)
        secureRandom.nextBytes(ivBytes)
        return encode(IvParameterSpec(ivBytes).iv)
    }

    /** Generates a Base64-encoded 12-byte IV for GCM mode. */
    open fun generateIVGCMParameterSpecKey(): String {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(12)
        secureRandom.nextBytes(ivBytes)
        return encode(GCMParameterSpec(128, ivBytes).iv)
    }

    open fun encrypt(
        secretKey: SecretKey,
        blockMode: CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        algorithmParameterSpec: AlgorithmParameterSpec,
        plainText: String,
    ): String = encrypt(
        secretKey = secretKey,
        transformation = buildTransformation(blockMode, padding),
        plainText = plainText,
        algorithmParameterSpec = algorithmParameterSpec,
    )

    open fun encrypt(
        secretKey: SecretKey,
        blockMode: CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        plainText: String,
    ): CryptoVaultEncryptedModel = encrypt(
        secretKey = secretKey,
        transformation = buildTransformation(blockMode, padding),
        plainText = plainText,
    )

    open fun encrypt(
        encodedSecretKey: String,
        blockMode: CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        algorithmParameterSpec: AlgorithmParameterSpec,
        plainText: String,
    ): String = encrypt(
        algorithm = algorithm,
        encodedSecretKey = encodedSecretKey,
        transformation = buildTransformation(blockMode, padding),
        plainText = plainText,
        algorithmParameterSpec = algorithmParameterSpec,
    )

    open fun encrypt(
        encodedSecretKey: String,
        blockMode: CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        plainText: String,
    ): CryptoVaultEncryptedModel = encrypt(
        algorithm = algorithm,
        encodedSecretKey = encodedSecretKey,
        transformation = buildTransformation(blockMode, padding),
        plainText = plainText,
    )

    open fun decrypt(
        secretKey: SecretKey,
        blockMode: CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encryptedText: String,
    ): String = decrypt(
        secretKey = secretKey,
        transformation = buildTransformation(blockMode, padding),
        encryptedText = encryptedText,
        algorithmParameterSpec = algorithmParameterSpec,
    )

    open fun decrypt(
        encodedSecretKey: String,
        blockMode: CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encryptedText: String,
    ): String = decrypt(
        algorithm = algorithm,
        transformation = buildTransformation(blockMode, padding),
        encodedSecretKey = encodedSecretKey,
        algorithmParameterSpec = algorithmParameterSpec,
        encryptedText = encryptedText,
    )

    private fun buildTransformation(
        blockMode: CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
    ): String = "${algorithm.name}/${blockMode.value}/${padding.value}"
}
