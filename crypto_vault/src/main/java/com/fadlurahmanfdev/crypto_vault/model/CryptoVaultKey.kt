package com.fadlurahmanfdev.crypto_vault.model

/**
 * Base64-encoded asymmetric key pair.
 *
 * @param privateKey Base64-encoded private key material.
 * @param publicKey Base64-encoded public key material.
 */
data class CryptoVaultKey(
    val privateKey: String,
    val publicKey: String,
)
