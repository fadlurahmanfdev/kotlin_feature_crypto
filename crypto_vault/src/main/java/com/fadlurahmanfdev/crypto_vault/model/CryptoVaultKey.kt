package com.fadlurahmanfdev.crypto_vault.model

/**
 * Base64-encoded asymmetric key pair.
 *
 * @param encodedPrivateKey Base64-encoded private key material.
 * @param encodedPublicKey Base64-encoded public key material.
 */
data class CryptoVaultKey(
    val encodedPrivateKey: ByteArray,
    val encodedPublicKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CryptoVaultKey

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
