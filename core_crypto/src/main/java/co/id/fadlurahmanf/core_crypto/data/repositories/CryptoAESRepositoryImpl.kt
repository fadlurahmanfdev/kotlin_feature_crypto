package co.id.fadlurahmanf.core_crypto.data.repositories

import co.id.fadlurahmanf.core_crypto.data.enums.AESMethod
import co.id.fadlurahmanf.core_crypto.others.BaseCrypto
import java.util.logging.Level
import java.util.logging.Logger
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

    override fun encrypt(encodedKey: String, plainText: String, method: AESMethod): String? {
        try {
            val cipher = Cipher.getInstance(getAESTransformationBasedOnFlow(method))
            val secretKey = SecretKeySpec(decode(encodedKey), "AES")
            val iv = IvParameterSpec(ByteArray(16))
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv)
            return encode(cipher.doFinal(plainText.toByteArray()))
        } catch (e: Throwable) {
            Logger.getLogger(CryptoAESRepository::class.java.simpleName)
                .log(Level.INFO, "failed encrypt: ${e.message}")
            return null
        }
    }

    override fun decrypt(encodedKey: String, encryptedText: String, method: AESMethod): String? {
        try {
            val cipher = Cipher.getInstance(getAESTransformationBasedOnFlow(method))
            val secretKey = SecretKeySpec(decode(encodedKey), "AES")
            val iv = IvParameterSpec(ByteArray(16))
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv)
            return String(cipher.doFinal(decode(encryptedText)))
        } catch (e: Exception) {
            Logger.getLogger(CryptoAESRepository::class.java.simpleName)
                .log(Level.INFO, "failed decrypt: ${e.message}")
            return null
        }
    }
}