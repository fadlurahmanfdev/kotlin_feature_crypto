package com.fadlurahmanfdev.crypto_vault.data.repositories

import com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultSignatureAlgorithm

interface CryptoRSARepository : CryptoKeyPairRepository {
    /**
     * Generate Signature
     *
     * @param encodedPrivateKey encoded private key
     * @param plainText text want to be convert into signature
     * @param signatureAlgorithm algorithm of signature want to be used
     *
     * @return encoded signature
     *
     * @see generateKey
     * @see CryptoVaultSignatureAlgorithm
     * */
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        signatureAlgorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultSignatureAlgorithm,
    ): String

    /**
     * Verify the signature
     *
     * @param encodedPublicKey encoded public key
     * @param signature signature want to be verified
     * @param plainText text want to be verified
     * @param signatureAlgorithm algorithm of signature want to be used
     *
     * @return [Boolean] is plain text verified with the given signature
     *
     * @see generateKey
     * @see generateSignature
     * @see CryptoVaultSignatureAlgorithm
     * */
    fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        signatureAlgorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultSignatureAlgorithm,
    ): Boolean

    /**
     * Encrypt the text
     *
     * @param encodedPublicKey encoded public key
     * @param plainText text want to be encrypted
     *
     * @return [String] encrypted text
     *
     * @see generateKey
     * */
    fun encrypt(
        encodedPublicKey: String,
        plainText: String,
    ): String

    /**
     * Decrypt the encrypted text
     *
     * @param encodedPrivateKey encoded private key
     * @param encryptedText encrypted text want to be decrypted
     *
     * @return [String] encrypted text
     *
     * @see generateKey
     * */
    fun decrypt(
        encodedPrivateKey: String,
        encryptedText: String,
    ): String
}