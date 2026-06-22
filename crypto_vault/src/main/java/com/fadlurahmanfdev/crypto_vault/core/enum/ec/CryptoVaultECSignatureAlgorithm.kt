package com.fadlurahmanfdev.crypto_vault.core.enum.ec

/**
 * ECDSA signature algorithms supported by [com.fadlurahmanfdev.crypto_vault.api.CryptoVaultEC].
 *
 * @property value JCA signature algorithm name passed to [java.security.Signature].
 */
enum class CryptoVaultECSignatureAlgorithm(val value: String) {
    SHA256withECDSA("SHA256withECDSA"),
}
