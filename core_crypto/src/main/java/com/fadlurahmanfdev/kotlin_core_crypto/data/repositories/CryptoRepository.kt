package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import javax.crypto.Cipher

interface CryptoRepository {
    /**
     * Check whether specified combination of algorithm, block mode, padding is supported.
     *
     * @param algorithm algorithm used to check if supported
     * @param blockMode block mode used to check if supported
     * @param padding padding used to check if supported
     *
     * @return [Boolean] is plain text verified with the given signature
     *
     * */
    fun isSupported(
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding
    ): Boolean {
        try {
            Cipher.getInstance("${algorithm.name}/${blockMode.value}/${padding.value}")
            return true
        } catch (e: Exception) {
            return false
        }
    }
}