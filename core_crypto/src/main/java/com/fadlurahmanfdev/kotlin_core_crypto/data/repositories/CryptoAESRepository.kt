package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod

interface CryptoAESRepository {
    fun generateSecureKey(): String
    fun generateKey(): String
    fun generateSecureIVKey(): String
    fun generateIVKey(): String
    fun encrypt(
        /**
         * encoded base64 key
         * @see CryptoAESRepository.generateKey
         * @see CryptoAESRepository.generateSecureKey
         * */
        key: String,
        /**
         * encoded base64 iv key
         * @see CryptoAESRepository.generateIVKey
         * @see CryptoAESRepository.generateSecureKey
         * */
        ivKey: String,
        plainText: String,
        method: AESMethod = AESMethod.AES_CBC_PKCS5PADDING
    ): String?

    fun decrypt(
        /**
         * encoded base64 key
         * @see CryptoAESRepository.generateKey
         * @see CryptoAESRepository.generateSecureKey
         * */
        key: String,
        /**
         * encoded base64 iv key
         * @see CryptoAESRepository.generateIVKey
         * @see CryptoAESRepository.generateSecureKey
         * */
        ivKey: String,
        encryptedText: String,
        method: AESMethod = AESMethod.AES_CBC_PKCS5PADDING
    ): String?
}