package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey

interface CryptoAsymmetricRepository : CryptoRepository {
    fun generateKey(algorithm: FeatureCryptoAlgorithm): CryptoKey

    fun generateSignature(
        /**
         * encoded private key, get from generateKey().privateKey
         * @see CryptoRSARepository.generateKey
         * */
        encodedPrivateKey: String,
        plainText: String,
        algorithm: FeatureCryptoAlgorithm,
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
        algorithm: FeatureCryptoAlgorithm,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm,
    ): Boolean

    fun encrypt(
        /**
         * encoded public key, get from generateKey().publicKey
         * @see CryptoRSARepository.generateKey
         * */
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        encodedPublicKey: String,
        plainText: String,
    ): String

    fun decrypt(
        /**
         * encoded private key, get from generateKey().privateKey
         * @see CryptoRSARepository.generateKey
         * */
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        encodedPrivateKey: String,
        encryptedText: String,
    ): String?
}