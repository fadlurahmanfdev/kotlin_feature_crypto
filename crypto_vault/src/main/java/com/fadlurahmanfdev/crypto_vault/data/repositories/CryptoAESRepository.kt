package com.fadlurahmanfdev.crypto_vault.data.repositories

interface CryptoAESRepository {
    /**
     * Generate AES key
     *
     * @return encoded key
     * */
    fun generateKey(): String

    /**
     * Generate iv key
     *
     * @return encoded iv key
     * */
    fun generateIVKey(): String

    /**
     * Encrypt text
     *
     * @see generateIVKey
     * */
    fun encrypt(
        key: String,
        ivKey: String,
        plainText: String,
    ): String

    /**
     * Decrypt the encrypted text
     *
     * @return plain text
     *
     * @see generateIVKey
     * @see encrypt
     * */
    fun decrypt(
        key: String,
        ivKey: String,
        encryptedText: String,
    ): String
}