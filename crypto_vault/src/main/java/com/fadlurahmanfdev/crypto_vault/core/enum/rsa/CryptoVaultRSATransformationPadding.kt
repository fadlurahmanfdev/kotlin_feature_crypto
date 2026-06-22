package com.fadlurahmanfdev.crypto_vault.core.enum.rsa

/**
 * RSA cipher paddings supported by [com.fadlurahmanfdev.crypto_vault.api.CryptoVaultRSA].
 *
 * @property value JCA padding segment used in `RSA/BlockMode/Padding` transformations.
 */
enum class CryptoVaultRSATransformationPadding(val value: String) {
    PKCS1Padding("PKCS1Padding"),
    OAEPWithSHAAndMGF1Padding("OAEPWithSHA-1AndMGF1Padding"),

    /** Not available in Android Keystore on all devices. */
    OAEPWithSHA256AndMGF1Padding("OAEPWithSHA-256AndMGF1Padding"),
}
