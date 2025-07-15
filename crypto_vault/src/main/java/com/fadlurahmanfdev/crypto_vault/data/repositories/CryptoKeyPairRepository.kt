package com.fadlurahmanfdev.crypto_vault.data.repositories

import com.fadlurahmanfdev.crypto_vault.data.model.CryptoVaultKey

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