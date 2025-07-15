package com.fadlurahmanfdev.example.domain

import com.fadlurahmanfdev.crypto_vault.data.model.CryptoVaultKey


interface ExampleCryptoUseCase {
    fun generateED25519Key(): CryptoVaultKey

    fun generateED25519Signature(
        encodedPrivateKey: String,
        plainText: String,
    ): String?

    fun exampleED25519()

    fun customSymmetricCrypto()

    fun customAsymmetricCrypto()
}