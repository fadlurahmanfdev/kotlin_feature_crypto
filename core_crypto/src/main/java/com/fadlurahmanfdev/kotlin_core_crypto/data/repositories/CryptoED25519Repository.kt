package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey

interface CryptoED25519Repository : CryptoKeyPairRepository {
    /**
     * Generate Signature
     *
     * @param encodedPrivateKey encoded private key
     * @param plainText text want to be convert into signature
     *
     * @return encoded signature
     *
     * @see generateKey
     * @see FeatureCryptoSignatureAlgorithm
     * */
    fun generateSignature(
        /**
         * encoded private key, get from generateKey().privateKey
         * @see generateKey
         * */
        encodedPrivateKey: String,
        plainText: String,
    ): String

    /**
     * Verify the signature
     *
     * @param encodedPublicKey encoded public key
     * @param signature signature want to be verified
     * @param plainText text want to be verified
     *
     * @return [Boolean] is plain text verified with the given signature
     *
     * @see generateKey
     * @see generateSignature
     * @see FeatureCryptoSignatureAlgorithm
     * */
    fun verifySignature(
        encodedPublicKey: String,
        plainText: String,
        signature: String,
    ): Boolean
}