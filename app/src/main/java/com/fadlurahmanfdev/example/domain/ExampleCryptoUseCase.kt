package com.fadlurahmanfdev.example.domain

import com.fadlurahmanfdev.kotlin_feature_crypto.data.model.CryptoKey


interface ExampleCryptoUseCase {
    fun exampleCryptoAES()
    fun exampleCryptoRSA()

    fun exampleCombineRSAAndAES()

    fun generateED25519Key(): CryptoKey

    fun generateED25519Signature(
        encodedPrivateKey: String,
        plainText: String,
    ): String?

    fun exampleED25519()

    fun exampleECKeyExchange()

    fun exampleEC()

    fun customSymmetricCrypto()

    fun customAsymmetricCrypto()
}