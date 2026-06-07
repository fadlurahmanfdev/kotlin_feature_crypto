package com.fadlurahmanfdev.crypto_vault.enum.ec

/**
 * Supported EC encryption schemes.
 *
 * [ECDH_AES_GCM] uses ephemeral ECDH key agreement with SHA-256 key derivation and AES-GCM.
 * This hybrid scheme is widely supported on Android without third-party JCE cipher aliases.
 */
enum class CryptoVaultECTransformation {
    ECDH_AES_GCM,
}
