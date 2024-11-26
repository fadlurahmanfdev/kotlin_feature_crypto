package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey

interface CryptoKeyPairRepository {
    /**
     * Generate Key Pair
     *
     * @return encoded key (private & public)
     *
     * @return [CryptoKey] encoded key (private & public)
     * */
    fun generateKey(): CryptoKey
}