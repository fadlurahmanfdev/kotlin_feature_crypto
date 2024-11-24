package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey

interface CryptoAsymmetricRepository : CryptoRepository {
    fun generateKey(): CryptoKey

    fun generateSignature(
        /**
         * encoded private key, get from generateKey().privateKey
         * @see CryptoRSARepository.generateKey
         * */
        privateKey: String,
        plainText: String,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm,
    ): String

    fun verifySignature(
        /**
         * encoded public key, get from generateKey().publicKey
         * @see CryptoRSARepository.generateKey
         * */
        encodedPublicKey: String,
        /**
         * encoded signature, get from generateSignature()
         * @see CryptoRSARepository.generateKey
         * */
        signature: String,
        plainText: String,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm,
    ): Boolean

    fun encrypt(
        /**
         * encoded public key, get from generateKey().publicKey
         * @see CryptoRSARepository.generateKey
         * */
        encodedPublicKey: String,
        plainText: String,
    ): String

    fun decrypt(
        /**
         * encoded private key, get from generateKey().privateKey
         * @see CryptoRSARepository.generateKey
         * */
        encodedPrivateKey: String,
        encryptedText: String,
    ): String?
}