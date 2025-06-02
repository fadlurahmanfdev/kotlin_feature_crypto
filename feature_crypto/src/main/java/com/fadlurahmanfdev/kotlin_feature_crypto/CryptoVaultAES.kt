package com.fadlurahmanfdev.kotlin_feature_crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.fadlurahmanfdev.kotlin_feature_crypto.core.commons.BaseCryptoVault
import com.fadlurahmanfdev.kotlin_feature_crypto.data.model.CryptoVaultEncryptedModel
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

class CryptoVaultAES : BaseCryptoVault() {
    fun isStrongBoxBackedSupported(keystoreAlias: String): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateKey(keystoreAlias, strongBoxBacked = true)
                return true
            } catch (e: StrongBoxUnavailableException) {
                return false
            } catch (e: Throwable) {
                throw e
            }
        } else {
            return false
        }
    }

    fun generateKey(keystoreAlias: String, strongBoxBacked: Boolean = false): SecretKey {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                keystoreAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).apply {
                setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                setKeySize(256)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(strongBoxBacked)
                }

                setRandomizedEncryptionRequired(false)
            }.build()
            return generateKeyFromAndroidKeyStore(keyGenParameterSpec)
        } else {
            return generateKey()
        }
    }

    fun generateKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        return keyGenerator.generateKey()
    }

    fun generateIVParameterSpecKey(size: Int): String {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(size)
        secureRandom.nextBytes(ivBytes)
        val ivParameterSpec = IvParameterSpec(ivBytes)
        return encode(ivParameterSpec.iv)
    }

    fun generateIVGCMParameterSpecKey(size: Int): String {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(size)
        secureRandom.nextBytes(ivBytes)
        val ivParameterSpec = GCMParameterSpec(128, ivBytes)
        return encode(ivParameterSpec.iv)
    }

    /**
     * Encrypt text using gcm parameter spec key custom.
     *
     * GCM Parameter Spec custom can be support by enable [KeyGenParameterSpec.Builder.setRandomizedEncryptionRequired]
     *
     * @param secretKey secret key get from [generateKey]
     *
     * */
    fun encrypt(secretKey: SecretKey, algorithmParameterSpec: AlgorithmParameterSpec, plainText: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            secretKey,
            algorithmParameterSpec,
        )
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    fun encrypt(secretKey: SecretKey, plainText: String): CryptoVaultEncryptedModel {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedText = encode(cipher.doFinal(plainText.toByteArray()))
        val ivKey = encode(cipher.iv)
        return CryptoVaultEncryptedModel(
            encryptedText = encryptedText,
            ivKey = ivKey
        )
    }

    fun decrypt(secretKey: SecretKey, parameterSpec: String, encryptedText: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, decode(parameterSpec)))
        return String(cipher.doFinal(decode(encryptedText)))
    }

    fun decrypt(secretKey: SecretKey, algorithmParameterSpec: AlgorithmParameterSpec, encryptedText: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}