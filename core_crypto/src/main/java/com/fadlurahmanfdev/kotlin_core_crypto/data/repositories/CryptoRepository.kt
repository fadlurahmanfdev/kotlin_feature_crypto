package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import javax.crypto.Cipher

interface CryptoRepository {
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