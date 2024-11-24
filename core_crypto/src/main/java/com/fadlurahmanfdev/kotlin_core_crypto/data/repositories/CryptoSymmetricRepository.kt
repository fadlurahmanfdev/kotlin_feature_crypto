package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

interface CryptoSymmetricRepository:CryptoRepository {
    fun generateKey(): String

    fun generateIVKey(): String

    fun encrypt(
        key: String,
        ivKey: String,
        plainText: String,
    ): String

    fun decrypt(
        key: String,
        ivKey: String,
        encryptedText: String,
    ): String
}