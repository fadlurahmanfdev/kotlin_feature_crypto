package com.fadlurahmanfdev.crypto_vault.api.enums.aes

/**
 * AES padding modes supported by [com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES].
 *
 * @property value JCA padding segment used in `AES/BlockMode/Padding` transformations.
 */
enum class CryptoVaultAESEncryptionPadding(val value: String) {
    NoPadding("NoPadding"),

    PKCS5Padding("PKCS5Padding"),

    PKCS7Padding("PKCS7Padding"),
}