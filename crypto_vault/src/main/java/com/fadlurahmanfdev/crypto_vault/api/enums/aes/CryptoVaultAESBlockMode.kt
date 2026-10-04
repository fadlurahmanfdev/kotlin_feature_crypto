package com.fadlurahmanfdev.crypto_vault.api.enums.aes

import android.security.keystore.KeyProperties

/**
 * AES block modes supported by [com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES].
 *
 * @property value JCA block mode segment used in `AES/BlockMode/Padding` transformations.
 */
enum class CryptoVaultAESBlockMode(val value: String) {
    /**
     * Get from [KeyProperties.BLOCK_MODE_GCM]
     * */
    GCM("GCM"),
    /**
     * Get from [KeyProperties.BLOCK_MODE_CBC]
     * */
    CBC("CBC"),
}
