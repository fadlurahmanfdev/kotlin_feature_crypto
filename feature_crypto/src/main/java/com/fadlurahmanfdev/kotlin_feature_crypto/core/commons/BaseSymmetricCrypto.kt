package com.fadlurahmanfdev.kotlin_feature_crypto.core.commons

import com.fadlurahmanfdev.kotlin_feature_crypto.core.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.core.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_feature_crypto.core.enums.FeatureCryptoPadding
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

abstract class BaseSymmetricCrypto : BaseCrypto() {
    /**
     * Generate key
     *
     * @param algorithm algorithm used for generate key
     *
     * @return encoded key
     * */
    fun generateKey(algorithm: FeatureCryptoAlgorithm): String {
        val key = KeyGenerator.getInstance(algorithm.name)
        return encode(key.generateKey().encoded)
    }

    /**
     * Generate Initialized Vector
     *
     * @return encoded iv key
     * */
    fun generateIVKey(size: Int): String {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(size)
        secureRandom.nextBytes(ivBytes)
        val ivParameterSpec = IvParameterSpec(ivBytes)
        return encode(ivParameterSpec.iv)
    }

    /**
     * Encrypt the text
     *
     * @param algorithm algorithm used for encryption
     * @param blockMode block mode used for encryption
     * @param padding padding used for encryption
     * @param key encoded key
     * @param ivKey encoded iv key
     * @param plainText plain text want to be encrypted
     *
     * @return encrypted text
     *
     * @see generateKey
     * @see generateIVKey
     * @see FeatureCryptoAlgorithm
     * @see FeatureCryptoBlockMode
     * @see FeatureCryptoPadding
     * */
    fun encrypt(
        algorithm: FeatureCryptoAlgorithm,
        transformation: String,
        key: String,
        ivKey: String,
        plainText: String,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        val secretKey = SecretKeySpec(decode(key), algorithm.name)
        val ivParameterSpec = IvParameterSpec(decode(ivKey))
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    /**
     * Decrypt the encrypted text
     *
     * @param algorithm algorithm used for encryption
     * @param blockMode block mode used for encryption
     * @param padding padding used for encryption
     * @param key encoded key
     * @param ivKey encoded iv key
     * @param encryptedText encrypted text want to be decrypted
     *
     * @return encrypted text
     *
     * @see generateKey
     * @see generateIVKey
     * @see encrypt
     * @see FeatureCryptoAlgorithm
     * @see FeatureCryptoBlockMode
     * @see FeatureCryptoPadding
     * */
    fun decrypt(
        algorithm: FeatureCryptoAlgorithm,
        transformation: String,
        key: String,
        ivKey: String,
        encryptedText: String,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        val secretKey = SecretKeySpec(decode(key), algorithm.name)
        val ivParameterSpec = IvParameterSpec(decode(ivKey))
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}