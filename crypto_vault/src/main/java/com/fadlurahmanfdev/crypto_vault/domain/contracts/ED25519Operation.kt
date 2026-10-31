package com.fadlurahmanfdev.crypto_vault.domain.contracts

import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKey

interface ED25519Operation {
    /** Generates an ED25519 key pair encoded as Base64. */
    fun generateKey(): CryptoVaultKey

    /** Signs [plainText] with the given Base64-encoded private key. */
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
    ): String

    /** Verifies an ED25519 signature for [plainText]. Returns false when verification fails. */
    fun verifySignature(
        encodedPublicKey: String,
        plainText: String,
        signature: String,
    ): Boolean
}