package com.fadlurahmanfdev.crypto_vault.core.enum

/**
 * Signature algorithms supported by [com.fadlurahmanfdev.crypto_vault.api.CryptoVaultCustomAsymmetricVault].
 */
enum class CryptoVaultSignatureAlgorithm {
    SHA1withRSA,
    SHA256withRSA,
    SHA512withRSA,
    MD5withRSA,
    SHA1withDSA,
    SHA256withDSA,
    ECDSA,
    Ed25519,
    Ed448,
}
