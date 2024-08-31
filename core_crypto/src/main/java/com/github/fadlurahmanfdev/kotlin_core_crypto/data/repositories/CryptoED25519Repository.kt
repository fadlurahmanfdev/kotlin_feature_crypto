package com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.github.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey

interface CryptoED25519Repository {
    fun generateKey(): CryptoKey

    fun generateSignature(
        /**
         * encoded private key, get from generateKey().privateKey
         * @see CryptoED25519Repository.generateKey
         * */
        privateKey: String,
        plainText: String,
    ): String?

    fun verifySignature(
        publicKey: String,
        plainText: String,
        signature: String,
        ): Boolean
}