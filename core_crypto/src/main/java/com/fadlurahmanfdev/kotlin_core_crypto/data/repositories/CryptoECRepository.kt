package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm

interface CryptoECRepository : CryptoKeyPairRepository {
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
     * @see FeatureCryptoSignatureAlgorithm
     * */
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm,
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
     * @see FeatureCryptoSignatureAlgorithm
     * */
    fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm,
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

    /**
     * Generate shared secret using our own private key & other public key.
     *
     * @param ourEncodedPrivateKey our private key in base64 encoded
     * @param otherEncodedPublicKey other channel public key in base64 encoded
     *
     * @return [String] encoded shared secret
     *
     * @see generateKey
     * */
    fun generateSharedSecret(
        ourEncodedPrivateKey: String,
        otherEncodedPublicKey: String
    ): String

    fun derivedSharedSecret(sharedSecret: String): String
}