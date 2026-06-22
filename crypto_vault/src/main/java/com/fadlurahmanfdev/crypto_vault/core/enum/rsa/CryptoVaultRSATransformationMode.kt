package com.fadlurahmanfdev.crypto_vault.core.enum.rsa

/**
 * RSA cipher block modes supported by [com.fadlurahmanfdev.crypto_vault.api.CryptoVaultRSA].
 *
 * @property value JCA block mode segment used in `RSA/BlockMode/Padding` transformations.
 */
enum class CryptoVaultRSATransformationMode(val value: String) {
    ECB("ECB"),
}
