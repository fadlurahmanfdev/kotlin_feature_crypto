package co.id.fadlurahmanf.core_crypto.data.repositories

import co.id.fadlurahmanf.core_crypto.data.enums.AESMethod

interface CryptoAESRepository {
    fun generateKey(): String
    fun encrypt(encodedKey: String, plainText: String, method: AESMethod): String?
    fun decrypt(encodedKey: String, encryptedText: String, method: AESMethod): String?
}