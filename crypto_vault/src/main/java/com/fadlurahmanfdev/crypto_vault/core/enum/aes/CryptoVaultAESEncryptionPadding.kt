package com.fadlurahmanfdev.crypto_vault.core.enum.aes

/**
 * AES padding modes supported by [com.fadlurahmanfdev.crypto_vault.api.CryptoVaultAES].
 *
 * @property value JCA padding segment used in `AES/BlockMode/Padding` transformations.
 */
enum class CryptoVaultAESEncryptionPadding(val value: String) {
    NoPadding("NoPadding"),
    PKCS5Padding("PKCS5Padding"),
}
