package com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.github.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey

interface CryptoED25519Repository {
    fun generateKey(): CryptoKey

    fun generateSignature(plainText: String, encodedPrivateKey: String): String?

    // TODO(dev): change signature to encoded signature
    // TODO(dev): change text to plain text
    fun verifySignature(text: String, signature: String, encodedPublicKey: String): Boolean
}