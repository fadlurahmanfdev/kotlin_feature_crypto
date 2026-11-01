package com.fadlurahmanfdev.crypto_vault.model

/**
 * Asymmetric key pair as raw encoded bytes.
 *
 * @param encodedPrivateKey Private key material (algorithm-specific encoding).
 * @param encodedPublicKey Public key material (algorithm-specific encoding).
 */
data class CryptoVaultKeyPair(
    val encodedPrivateKey: ByteArray,
    val encodedPublicKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CryptoVaultKeyPair

        if (!encodedPrivateKey.contentEquals(other.encodedPrivateKey)) return false
        if (!encodedPublicKey.contentEquals(other.encodedPublicKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encodedPrivateKey.contentHashCode()
        result = 31 * result + encodedPublicKey.contentHashCode()
        return result
    }
}
