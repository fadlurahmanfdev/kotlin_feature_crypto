package com.fadlurahmanfdev.kotlin_feature_crypto

import com.fadlurahmanfdev.kotlin_feature_crypto.core.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.core.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_feature_crypto.core.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories.CryptoAESRepository
import com.fadlurahmanfdev.kotlin_feature_crypto.core.commons.BaseSymmetricCrypto

class FeatureCryptoAES : BaseSymmetricCrypto(), CryptoAESRepository {
    /**
     * Generate AES Key
     *
     * @return encoded aes key
     *
     * @see BaseSymmetricCrypto.generateKey
     * */
    override fun generateKey(): String {
        return super.generateKey(FeatureCryptoAlgorithm.AES)
    }

    /**
     * Encrypt using aes method
     *
     * @return encrypted text
     *
     * @see generateKey
     * @see generateIVKey
     * */
    override fun encrypt(
        key: String,
        ivKey: String,
        plainText: String
    ): String {
        return super.encrypt(
            algorithm = FeatureCryptoAlgorithm.AES,
            transformation = "${FeatureCryptoAlgorithm.AES}/${FeatureCryptoBlockMode.GCM}/${FeatureCryptoPadding.NoPadding}",
            key = key,
            ivKey = ivKey,
            plainText = plainText
        )
    }

    override fun generateIVKey(): String {
        return super.generateIVKey(16)
    }

    /**
     * Decrypt the encrypted text.
     *
     * @return plain text
     *
     * @see generateKey
     * @see generateIVKey
     * @see encrypt
     * */
    override fun decrypt(
        key: String,
        ivKey: String,
        encryptedText: String
    ): String {
        return super.decrypt(
            algorithm = FeatureCryptoAlgorithm.AES,
            transformation = "${FeatureCryptoAlgorithm.AES}/${FeatureCryptoBlockMode.GCM}/${FeatureCryptoPadding.NoPadding}",
            key = key,
            ivKey = ivKey,
            encryptedText = encryptedText
        )
    }
}