package com.fadlurahmanfdev.crypto_vault.model

/**
 * Asymmetric key pair as raw key bytes.
 *
 * @param privateKeyBytes Private key material (algorithm-specific encoding).
 * @param publicKeyBytes Public key material (algorithm-specific encoding).
 */
data class CryptoVaultKeyPair(
    val privateKeyBytes: ByteArray,
    val publicKeyBytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CryptoVaultKeyPair

        if (!privateKeyBytes.contentEquals(other.privateKeyBytes)) return false
        if (!publicKeyBytes.contentEquals(other.publicKeyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = privateKeyBytes.contentHashCode()
        result = 31 * result + publicKeyBytes.contentHashCode()
        return result
    }
}
