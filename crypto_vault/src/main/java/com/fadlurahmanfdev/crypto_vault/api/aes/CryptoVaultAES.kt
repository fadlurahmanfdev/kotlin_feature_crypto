package com.fadlurahmanfdev.crypto_vault.api.aes

import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESTransformation
import com.fadlurahmanfdev.crypto_vault.domain.contracts.CryptoVaultAESV2Operation
import com.fadlurahmanfdev.crypto_vault.domain.models.EncryptedData
import com.fadlurahmanfdev.crypto_vault.internal.SoftwareKeyAESOperation
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

class CryptoVaultAES internal  constructor(
    private val operation: CryptoVaultAESV2Operation,
) {
    companion object {
        fun create(): CryptoVaultAES {
            return CryptoVaultAES(
                operation = SoftwareKeyAESOperation(),
            )
        }
    }

    fun generateIVParameterSpecKey(): IvParameterSpec = operation.generateIVParameterSpecKey()

    fun generateGCMParameterSpecKey(): GCMParameterSpec = operation.generateGCMParameterSpec()

    fun encrypt(
        secretKey: SecretKey,
        plainText: String,
        transformation: CryptoVaultAESTransformation,
        algorithmParameterSpec: AlgorithmParameterSpec
    ): ByteArray = operation.encrypt(secretKey, plainText, transformation, algorithmParameterSpec)

    fun encrypt(
        secretKey: SecretKey,
        plainText: String,
        transformation: CryptoVaultAESTransformation,
    ): EncryptedData = operation.encrypt(secretKey, plainText, transformation)

    fun decrypt(
        secretKey: SecretKey,
        transformation: CryptoVaultAESTransformation,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encrypted: ByteArray
    ): String = operation.decrypt(secretKey, transformation, algorithmParameterSpec, encrypted)
}
