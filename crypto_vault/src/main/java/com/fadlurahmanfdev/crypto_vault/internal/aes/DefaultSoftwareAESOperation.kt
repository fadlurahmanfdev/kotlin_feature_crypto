package com.fadlurahmanfdev.crypto_vault.internal.aes

import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.domain.contracts.AESSoftwareOperation
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.model.EncryptedData
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal class DefaultSoftwareAESOperation(
    private val keyGeneratorFactory: () -> KeyGenerator = {
        KeyGenerator.getInstance(AesTransformation.ALGORITHM)
    },
    private val cipherFactory: (transformation: String) -> Cipher = { transformation ->
        Cipher.getInstance(transformation)
    },
    private val secureRandomFactory: () -> SecureRandom = { SecureRandom() },
) : AESSoftwareOperation {

    companion object {
        fun create(): DefaultSoftwareAESOperation = DefaultSoftwareAESOperation()
    }

    override fun generateKey(keySize: Int): SecretKey {
        if (keySize !in AesTransformation.SUPPORTED_KEY_SIZES) {
            throw CryptoVaultExceptionCodes.invalidKeySize(
                message = "AES key size must be one of ${AesTransformation.SUPPORTED_KEY_SIZES}, but was $keySize",
            )
        }
        return try {
            val keyGenerator = keyGeneratorFactory()
            keyGenerator.init(keySize, secureRandomFactory())
            keyGenerator.generateKey()
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to generate AES key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun parseKey(key: ByteArray): SecretKey {
        return SecretKeySpec(key, AesTransformation.ALGORITHM)
    }

    override fun generateGCMParameterSpec(ivSizeBytes: Int, tagLengthBits: Int): GCMParameterSpec {
        val ivBytes = ByteArray(ivSizeBytes)
        secureRandomFactory().nextBytes(ivBytes)
        return GCMParameterSpec(tagLengthBits, ivBytes)
    }

    override fun generateIvParameterSpec(ivSizeBytes: Int): IvParameterSpec {
        val ivBytes = ByteArray(ivSizeBytes)
        secureRandomFactory().nextBytes(ivBytes)
        return IvParameterSpec(ivBytes)
    }

    override fun encrypt(
        secretKey: SecretKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
    ): EncryptedData {
        return try {
            val cipher = cipherFactory(AesTransformation.raw(blockMode, padding))
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            EncryptedData(
                text = cipher.doFinal(plainText),
                iv = cipher.iv,
            )
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to encrypt with software AES key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun encrypt(
        secretKey: SecretKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(AesTransformation.raw(blockMode, padding))
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec)
            cipher.doFinal(plainText)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to encrypt with software AES key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun decrypt(
        secretKey: SecretKey,
        encrypted: ByteArray,
        iv: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        val algorithmParameterSpec = when (blockMode) {
            AesTransformation.DEFAULT_BLOCK_MODE ->
                GCMParameterSpec(AesTransformation.GCM_TAG_LENGTH_BITS, iv)
            AesTransformation.BLOCK_MODE_CBC -> IvParameterSpec(iv)
            else -> throw CryptoVaultExceptionCodes.invalidBlockMode(
                message = "Block mode \"$blockMode\" needs AlgorithmParameterSpec overload for decrypt",
            )
        }
        return decrypt(
            secretKey = secretKey,
            encrypted = encrypted,
            blockMode = blockMode,
            padding = padding,
            algorithmParameterSpec = algorithmParameterSpec,
        )
    }

    override fun decrypt(
        secretKey: SecretKey,
        encrypted: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(AesTransformation.raw(blockMode, padding))
            cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec)
            cipher.doFinal(encrypted)
        } catch (e: AEADBadTagException) {
            throw CryptoVaultExceptionCodes.integrityCheckFailed(
                message = "Ciphertext or IV was modified, or does not belong to this key",
                cause = e,
            )
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to decrypt with software AES key: ${e.message}",
                cause = e,
            )
        }
    }
}
