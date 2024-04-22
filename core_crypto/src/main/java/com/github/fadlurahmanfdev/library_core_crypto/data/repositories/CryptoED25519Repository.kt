package com.github.fadlurahmanfdev.library_core_crypto.data.repositories

import com.github.fadlurahmanfdev.library_core_crypto.data.model.CryptoKey

interface CryptoED25519Repository {
    fun generateKey(): CryptoKey

    fun generateSignature(plainText: String, encodedPrivateKey: String): String?

    fun verifySignature(text: String, signature: String, encodedPublicKey: String): Boolean
}