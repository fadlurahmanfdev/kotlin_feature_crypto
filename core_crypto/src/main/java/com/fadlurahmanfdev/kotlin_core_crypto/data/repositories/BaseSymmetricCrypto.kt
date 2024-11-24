package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_core_crypto.others.BaseCrypto
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

abstract class BaseSymmetricCrypto : BaseCrypto(), CryptoSymmetricRepository {
    fun generateKey(algorithm: FeatureCryptoAlgorithm): String {
        val key = KeyGenerator.getInstance(algorithm.name)
        return encode(key.generateKey().encoded)
    }

    override fun generateIVKey(): String {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(16)
        secureRandom.nextBytes(ivBytes)
        val ivParameterSpec = IvParameterSpec(ivBytes)
        return encode(ivParameterSpec.iv)
    }

    fun encrypt(
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        key: String,
        ivKey: String,
        plainText: String,
    ): String {
        val cipher = Cipher.getInstance("${algorithm.name}/${blockMode.value}/${padding.value}")
        val secretKey = SecretKeySpec(decode(key), algorithm.name)
        val ivParameterSpec = IvParameterSpec(decode(ivKey))
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    fun decrypt(
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        key: String,
        ivKey: String,
        encryptedText: String,
    ): String {
        val cipher = Cipher.getInstance("${algorithm.name}/${blockMode.value}/${padding.value}")
        val secretKey = SecretKeySpec(decode(key), algorithm.name)
        val ivParameterSpec = IvParameterSpec(decode(ivKey))
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}