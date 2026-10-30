package com.fadlurahmanfdev.crypto_vault.domain.contracts

import com.fadlurahmanfdev.crypto_vault.domain.models.EncryptedData
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

/**
 * Internal contract for software AES key lifecycle and cipher operations.
 */
interface CryptoVaultAESSoftwareOperation {
    fun generateKey(keySize: Int): SecretKey

    fun parseKey(key: ByteArray): SecretKey

    fun generateGCMParameterSpec(ivSizeBytes: Int, tagLengthBits: Int): GCMParameterSpec

    fun generateIvParameterSpec(ivSizeBytes: Int): IvParameterSpec

    fun encrypt(
        secretKey: SecretKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
    ): EncryptedData

    fun encrypt(
        secretKey: SecretKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray

    fun decrypt(
        secretKey: SecretKey,
        encrypted: ByteArray,
        iv: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray

    fun decrypt(
        secretKey: SecretKey,
        encrypted: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray
}
