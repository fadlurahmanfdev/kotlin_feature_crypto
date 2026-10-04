package com.fadlurahmanfdev.crypto_vault.domain.contracts

import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESTransformation
import com.fadlurahmanfdev.crypto_vault.domain.models.EncryptedData
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

/**
 * Contract for AES operations using keys generated in software (outside Android Keystore).
 */
interface CryptoVaultAESV2Operation {
    fun generateIVParameterSpecKey(): IvParameterSpec

    fun generateGCMParameterSpec(): GCMParameterSpec

    fun encrypt(
        secretKey: SecretKey,
        plainText: String,
        transformation : CryptoVaultAESTransformation,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray

    fun encrypt(
        secretKey: SecretKey,
        plainText: String,
        transformation : CryptoVaultAESTransformation,
    ): EncryptedData

    fun decrypt(
        secretKey: SecretKey,
        transformation: CryptoVaultAESTransformation,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encrypted: ByteArray,
    ): String
}
