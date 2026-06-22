package com.fadlurahmanfdev.crypto_vault.core.enum.rsa

/**
 * RSA encryption paddings accepted by Android Keystore key generation.
 *
 * @property value Android Keystore [android.security.keystore.KeyProperties] padding constant.
 */
enum class CryptoVaultRSAEncryptionPadding(val value: String) {
    RSA_PKCS1("PKCS1Padding"),
    RSA_OAEP("OAEPPadding"),
}
