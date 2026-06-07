package com.fadlurahmanfdev.crypto_vault.model

/**
 * Encrypted payload produced when the cipher generates its own IV.
 *
 * @param encryptedText Base64-encoded ciphertext.
 * @param ivKey Base64-encoded initialization vector.
 */
data class CryptoVaultEncryptedModel(
    val encryptedText: String,
    val ivKey: String,
)
