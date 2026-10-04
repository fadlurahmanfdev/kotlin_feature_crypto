package com.fadlurahmanfdev.crypto_vault.internal

import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESTransformation
import com.fadlurahmanfdev.crypto_vault.api.enums.aes.rawTransformation
import com.fadlurahmanfdev.crypto_vault.domain.contracts.CryptoVaultAESV2Operation
import com.fadlurahmanfdev.crypto_vault.domain.models.EncryptedData
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

internal class SoftwareKeyAESOperation : CryptoVaultAESV2Operation {
    override fun generateIVParameterSpecKey(): IvParameterSpec {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(16)
        secureRandom.nextBytes(ivBytes)
        return IvParameterSpec(ivBytes)
    }

    override fun generateGCMParameterSpec(): GCMParameterSpec {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(12)
        secureRandom.nextBytes(ivBytes)
        return GCMParameterSpec(128, ivBytes)
    }

    override fun encrypt(
        secretKey: SecretKey,
        plainText: String,
        transformation: CryptoVaultAESTransformation,
        algorithmParameterSpec: AlgorithmParameterSpec
    ): ByteArray {
        val cipher = Cipher.getInstance(transformation.rawTransformation())
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec)
        return cipher.doFinal(plainText.toByteArray())
    }

    override fun encrypt(
        secretKey: SecretKey,
        plainText: String,
        transformation: CryptoVaultAESTransformation
    ): EncryptedData {
        val cipher = Cipher.getInstance(transformation.rawTransformation())
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return EncryptedData(
            text = cipher.doFinal(plainText.toByteArray()),
            iv = cipher.iv,
        )
    }

    override fun decrypt(
        secretKey: SecretKey,
        transformation: CryptoVaultAESTransformation,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encrypted: ByteArray
    ): String {
        val cipher = Cipher.getInstance(transformation.rawTransformation())
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec)
        return String(cipher.doFinal(encrypted))
    }
}
