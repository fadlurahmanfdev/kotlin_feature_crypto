package com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import android.util.Log
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.others.BaseCrypto
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class CryptoAESRepositoryImpl : BaseCrypto(), CryptoAESRepository {
    override fun generateKey(): String {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        return encode(keyGen.generateKey().encoded)
    }

    override fun generateIVKey(): String {
        val ivParameterSpec = IvParameterSpec(ByteArray(16))
        return encode(ivParameterSpec.iv)
    }

    override fun encrypt(
        encodedKey: String,
        encodedIVKey: String,
        plainText: String,
        method: AESMethod
    ): String? {
        try {
            val cipher = Cipher.getInstance(getAESTransformationBasedOnFlow(method))
            val secretKey = SecretKeySpec(decode(encodedKey), "AES")
            val ivParameterSpec = IvParameterSpec(decode(encodedIVKey))
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
            return encode(cipher.doFinal(plainText.toByteArray()))
        } catch (e: Throwable) {
            Log.e(CryptoAESRepositoryImpl::class.java.simpleName, "failed encrypt: ${e.message}")
            return null
        }
    }

    override fun decrypt(
        encodedKey: String,
        encodedIVKey: String,
        encryptedText: String,
        method: AESMethod
    ): String? {
        try {
            val cipher = Cipher.getInstance(getAESTransformationBasedOnFlow(method))
            val secretKey = SecretKeySpec(decode(encodedKey), "AES")
            val iv = IvParameterSpec(decode(encodedIVKey))
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv)
            return String(cipher.doFinal(decode(encryptedText)))
        } catch (e: Exception) {
            Log.e(CryptoAESRepositoryImpl::class.java.simpleName, "failed decrypt: ${e.message}")
            return null
        }
    }
}