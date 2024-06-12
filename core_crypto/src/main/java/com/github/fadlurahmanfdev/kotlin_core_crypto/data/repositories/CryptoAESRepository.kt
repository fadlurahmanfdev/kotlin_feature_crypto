package com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod

interface CryptoAESRepository {
    fun generateKey(): String
    fun generateIVKey(): String
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