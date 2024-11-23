package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import android.util.Log
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_core_crypto.others.BaseCrypto
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class CustomCryptoSymmetricRepositoryImpl : BaseCrypto(), CryptoSymmetricRepository {
    override fun generateKey(algorithm: FeatureCryptoAlgorithm): String {
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

    override fun encrypt(
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        encodedKey: String,
        encodedIVKey: String,
        plainText: String,
    ): String {
        val cipher = Cipher.getInstance("${algorithm.name}/${blockMode.value}/${padding.value}")
        val secretKey = SecretKeySpec(decode(encodedKey), algorithm.name)
        val ivParameterSpec = IvParameterSpec(decode(encodedIVKey))
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    override fun decrypt(
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        encodedKey: String,
        encodedIVKey: String,
        encryptedText: String,
    ): String {
        val cipher = Cipher.getInstance("${algorithm.name}/${blockMode.value}/${padding.value}")
        val secretKey = SecretKeySpec(decode(encodedKey), algorithm.name)
        val ivParameterSpec = IvParameterSpec(decode(encodedIVKey))
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}