package com.fadlurahmanfdev.crypto_vault.core.enum.rsa

/**
 * RSA signature paddings accepted by Android Keystore key generation.
 *
 * @property value Android Keystore [android.security.keystore.KeyProperties] padding constant.
 */
enum class CryptoVaultRSASignaturePadding(val value: String) {
    RSA_PKCS1("PKCS1"),

    /** Not available in Android Keystore on all devices. */
    RSA_PSS("PSS"),
}
