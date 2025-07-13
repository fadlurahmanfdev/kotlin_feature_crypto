package com.fadlurahmanfdev.kotlin_feature_crypto.base

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.kotlin_feature_crypto.constant.CryptoVaultExceptionConstant
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.data.model.CryptoVaultEncryptedModel
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

abstract class BaseKeyCryptoVault : BaseCryptoVault() {
    /**
     * Generate key
     *
     * @param algorithm algorithm used for generate key
     *
     * @return encoded key
     * */
    fun generateKey(algorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm): String {
        val key = KeyGenerator.getInstance(algorithm.name)
        return encode(key.generateKey().encoded)
    }

    /**
     * Generate key from AndroidKeyStore
     *
     * @param keyGenParameterSpec parameter specification for the key
     *
     * @throws [CryptoVaultExceptionConstant.STRONG_BOX_NOT_SUPPORTED] if strong box backed not supported
     * */
    @RequiresApi(Build.VERSION_CODES.M)
    fun generateKeyFromAndroidKeyStore(
        algorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm,
        keyGenParameterSpec: KeyGenParameterSpec,
    ): SecretKey {
        try {
            val keyGenerator =
                KeyGenerator.getInstance(algorithm.name, "AndroidKeyStore")
            keyGenerator.init(keyGenParameterSpec)
            val secretKey = keyGenerator.generateKey()
            return secretKey
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (e is StrongBoxUnavailableException) {
                    throw CryptoVaultExceptionConstant.STRONG_BOX_NOT_SUPPORTED.copy(message = e.message)
                }
            }
            throw CryptoVaultExceptionConstant.UNKNOWN.copy(message = e.message)
        }
    }

    /**
     * Load key from AndroidKeyStore
     *
     * if the key is not exist in AndroidKeyStore, it will return null
     *
     * @param keystoreAlias Key identifier
     * */
    fun getKeyFromAndroidKeyStore(keystoreAlias: String): SecretKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(keystoreAlias, null) as SecretKey?
    }

    /**
     * Encrypt plain text using Secret key from Android Keystore
     *
     * GCM Parameter Spec custom can be support by enable [KeyGenParameterSpec.Builder.setRandomizedEncryptionRequired]
     *
     * @param secretKey secret key get from [generateKeyFromAndroidKeyStore].
     * @param transformation transformation of the encryption.
     * @param plainText plain text want to be encrypted.
     * @param algorithmParameterSpec parameter spec will be used (IV or IV GCM).
     *
     * */
    fun encrypt(
        secretKey: SecretKey,
        transformation: String,
        plainText: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            secretKey,
            algorithmParameterSpec,
        )
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    /**
     * Encrypt plain text using Secret key from Android Keystore.
     *
     * IV will be generated from cipher
     *
     * @param secretKey secret key get from [generateKeyFromAndroidKeyStore]
     * @param transformation transformation of the encryption.
     * @param plainText text want to be encrypted
     *
     * @return [CryptoVaultEncryptedModel] encoded encrypted text & encoded iv key
     *
     * */
    fun encrypt(
        secretKey: SecretKey,
        transformation: String,
        plainText: String,
    ): CryptoVaultEncryptedModel {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedText = encode(cipher.doFinal(plainText.toByteArray()))
        val ivKey = encode(cipher.iv)
        return CryptoVaultEncryptedModel(
            encryptedText = encryptedText,
            ivKey = ivKey
        )
    }

    /**
     * Encrypt plain text using Secret Key Non Android KeyStore
     *
     * @param algorithm algorithm of the encryption.
     * @param encodedSecretKey encoded secret key.
     * @param transformation transformation of the encryption.
     * @param plainText plain text want to be encrypted.
     * @param algorithmParameterSpec Parameter spec will be used (IV or IV GCM).
     *
     * */
    fun encrypt(
        algorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm,
        encodedSecretKey: String,
        transformation: String,
        plainText: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): String {
        val secretKey = SecretKeySpec(decode(encodedSecretKey), algorithm.name)
        val cipher = Cipher.getInstance(transformation)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            secretKey,
            algorithmParameterSpec,
        )
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    /**
     * Encrypt plain text using Secret Key Non Android KeyStore
     *
     * IV will be generated from cipher
     *
     * @param algorithm algorithm of encryption/
     * @param encodedSecretKey encoded secret key.
     * @param transformation transformation of the encryption.
     * @param plainText text want to be encrypted.
     *
     * */
    fun encrypt(
        algorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm,
        encodedSecretKey: String,
        transformation: String,
        plainText: String,
    ): CryptoVaultEncryptedModel {
        val secretKey = SecretKeySpec(decode(encodedSecretKey), algorithm.name)
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedText = encode(cipher.doFinal(plainText.toByteArray()))
        val ivKey = encode(cipher.iv)
        return CryptoVaultEncryptedModel(
            encryptedText = encryptedText,
            ivKey = ivKey
        )
    }

    /**
     * Decrypt encrypted text using Secret key from Android Keystore
     *
     * @param secretKey secret key from Android Keystore.
     * @param transformation transformation of the encryption.
     * @param encryptedText encrypted text want to be decrypt.
     * @param algorithmParameterSpec algorithm parameter spec from iv/iv gcm
     *
     * @return [String] decrypted text
     *
     * */
    fun decrypt(
        secretKey: SecretKey,
        transformation: String,
        encryptedText: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec)
        return String(cipher.doFinal(decode(encryptedText)))
    }

    /**
     * Decrypt the encrypted text
     *
     * @param algorithm algorithm used for encryption.
     * @param transformation transformation of the encryption.
     * @param encodedSecretKey encoded secret key.
     * @param algorithmParameterSpec algorithm parameter spec from iv/iv gcm
     * @param encryptedText encrypted text want to be decrypted
     *
     * @return [String] decrypted text
     *
     * */
    fun decrypt(
        algorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm,
        transformation: String,
        encodedSecretKey: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encryptedText: String,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        val secretKey = SecretKeySpec(decode(encodedSecretKey), algorithm.name)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}