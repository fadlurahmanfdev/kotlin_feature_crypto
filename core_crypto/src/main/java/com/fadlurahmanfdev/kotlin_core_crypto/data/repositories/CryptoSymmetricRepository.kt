package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding

interface CryptoSymmetricRepository:CryptoRepository {
    fun generateKey(algorithm: FeatureCryptoAlgorithm): String

    fun generateIVKey(): String

    fun encrypt(
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        encodedKey: String,
        encodedIVKey: String,
        plainText: String,
    ): String

    fun decrypt(
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        encodedKey: String,
        encodedIVKey: String,
        encryptedText: String,
    ): String
}