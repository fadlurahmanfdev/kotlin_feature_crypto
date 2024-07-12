package com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod

interface CryptoAESRepository {
    fun generateSecureKey(): String
    fun generateKey(): String
    fun generateSecureIVKey(): String
    fun generateIVKey(): String
    fun secureEncrypt(
        encodedSecureKey: String,
        plainText: String,
        method: AESMethod = AESMethod.AES_CBC_PKCS5PADDING
    ): String?
    fun secureDecrypt(
        encodedSecureKey: String,
        encryptedText: String,
        method: AESMethod = AESMethod.AES_CBC_PKCS5PADDING
    ): String?
    fun encrypt(
        encodedKey: String,
        encodedIVKey: String,
        plainText: String,
        method: AESMethod = AESMethod.AES_CBC_PKCS5PADDING
    ): String?

    fun decrypt(
        encodedKey: String,
        encodedIVKey: String,
        encryptedText: String,
        method: AESMethod = AESMethod.AES_CBC_PKCS5PADDING
    ): String?
}