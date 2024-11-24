package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding

class CryptoAESRepositoryImpl : BaseSymmetricCrypto(), CryptoSymmetricRepository {
    override fun generateKey(): String {
        return super.generateKey(FeatureCryptoAlgorithm.AES)
    }

    override fun encrypt(
        key: String,
        ivKey: String,
        plainText: String
    ): String {
        return super.encrypt(
            algorithm = FeatureCryptoAlgorithm.AES,
            blockMode = FeatureCryptoBlockMode.GCM,
            padding = FeatureCryptoPadding.NoPadding,
            key = key,
            ivKey = ivKey,
            plainText = plainText
        )
    }

    override fun decrypt(
        key: String,
        ivKey: String,
        encryptedText: String
    ): String {
        return super.decrypt(
            algorithm = FeatureCryptoAlgorithm.AES,
            blockMode = FeatureCryptoBlockMode.GCM,
            padding = FeatureCryptoPadding.NoPadding,
            key = key,
            ivKey = ivKey,
            encryptedText = encryptedText
        )
    }
}