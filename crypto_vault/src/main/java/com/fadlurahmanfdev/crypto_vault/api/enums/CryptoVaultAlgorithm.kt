package com.fadlurahmanfdev.crypto_vault.api.enums

/**
 * Supported cryptographic algorithms for custom vault operations.
 */

enum class CryptoVaultAlgorithm(val value: String? = null) {
    AES("AES"),
    DES,
    THREE_DES,
    ChaCha20,
    RSA(),
    EC,
    DSA,
}