package com.fadlurahmanfdev.crypto_vault.domain.contracts

import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKeyPair

interface ED25519Operation {
    /** Generates an ED25519 key pair as raw key bytes. */
    fun generateKey(): CryptoVaultKeyPair

    /** Signs [plainTextBytes] with the given raw private key bytes. */
    fun generateSignature(
        privateKeyBytes: ByteArray,
        plainTextBytes: ByteArray,
    ): ByteArray

    /**
     * Verifies an ED25519 signature for [plainTextBytes].
     *
     * Returns `false` when verification fails cryptographically.
     */
    fun verifySignature(
        publicKeyBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureBytes: ByteArray,
    ): Boolean
}
