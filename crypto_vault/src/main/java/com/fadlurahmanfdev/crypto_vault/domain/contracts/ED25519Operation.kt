package com.fadlurahmanfdev.crypto_vault.domain.contracts

import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKeyPair

interface ED25519Operation {
    /** Generates an ED25519 key pair as raw key bytes. */
    fun generateKey(): CryptoVaultKeyPair

    /** Signs [plainText] with the given raw private key bytes. */
    fun generateSignature(
        encodedPrivateKey: ByteArray,
        plainText: ByteArray,
    ): ByteArray

    /**
     * Verifies an ED25519 signature for [plainText].
     *
     * Returns `false` when verification fails cryptographically.
     */
    fun verifySignature(
        encodedPublicKey: ByteArray,
        plainText: ByteArray,
        signature: ByteArray,
    ): Boolean
}
