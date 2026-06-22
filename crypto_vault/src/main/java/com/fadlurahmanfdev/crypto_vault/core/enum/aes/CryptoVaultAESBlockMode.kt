package com.fadlurahmanfdev.crypto_vault.core.enum.aes

/**
 * AES block modes supported by [com.fadlurahmanfdev.crypto_vault.api.CryptoVaultAES].
 *
 * @property value JCA block mode segment used in `AES/BlockMode/Padding` transformations.
 */
enum class CryptoVaultAESBlockMode(val value: String) {
    GCM("GCM"),
    CBC("CBC"),
}
