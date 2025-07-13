package com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_feature_crypto.data.model.CryptoVaultKey

interface CryptoKeyPairRepository {
    /**
     * Generate Key Pair
     *
     * @return encoded key (private & public)
     *
     * @return [CryptoVaultKey] encoded key (private & public)
     * */
    fun generateKey(): CryptoVaultKey
}