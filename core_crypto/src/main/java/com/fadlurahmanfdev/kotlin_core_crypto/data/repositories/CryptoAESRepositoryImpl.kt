package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_core_crypto.others.BaseSymmetricCrypto

class CryptoAESRepositoryImpl : BaseSymmetricCrypto(), CryptoSymmetricRepository {
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
            blockMode = FeatureCryptoBlockMode.GCM,
            padding = FeatureCryptoPadding.NoPadding,
            key = key,
            ivKey = ivKey,
            plainText = plainText
        )
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
            blockMode = FeatureCryptoBlockMode.GCM,
            padding = FeatureCryptoPadding.NoPadding,
            key = key,
            ivKey = ivKey,
            encryptedText = encryptedText
        )
    }
}