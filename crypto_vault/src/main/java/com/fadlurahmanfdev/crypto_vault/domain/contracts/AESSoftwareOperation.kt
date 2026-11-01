package com.fadlurahmanfdev.crypto_vault.domain.contracts

import com.fadlurahmanfdev.crypto_vault.model.EncryptedData
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

/**
 * Internal contract for software AES key lifecycle and cipher operations.
 */
interface AESSoftwareOperation {
    fun generateKey(keySize: Int): SecretKey

    fun parseKey(keyBytes: ByteArray): SecretKey

    fun generateGCMParameterSpec(ivSizeBytes: Int, tagLengthBits: Int): GCMParameterSpec

    fun generateIvParameterSpec(ivSizeBytes: Int): IvParameterSpec

    fun encrypt(
        secretKey: SecretKey,
        plainTextBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): EncryptedData

    fun encrypt(
        secretKey: SecretKey,
        plainTextBytes: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray

    fun decrypt(
        secretKey: SecretKey,
        encryptedBytes: ByteArray,
        ivBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray

    fun decrypt(
        secretKey: SecretKey,
        encryptedBytes: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray
}
