package com.fadlurahmanfdev.example.presentation

import androidx.lifecycle.ViewModel
import com.fadlurahmanfdev.crypto_vault.data.model.CryptoVaultKey
import com.fadlurahmanfdev.example.domain.ExampleCryptoUseCase

class MainViewModel(
    private val exampleCryptoUseCase: ExampleCryptoUseCase
) : ViewModel() {

    // AES
    private lateinit var encodedAESKey: String
    private lateinit var encryptedAESText: String

    // RSA
    private lateinit var rsaKey: CryptoVaultKey
    private lateinit var encryptedAESKey: String
    private lateinit var encryptedRSAText: String
    private lateinit var signatureRSA: String

    // ED25519
    private lateinit var ed25519Key: CryptoVaultKey
    private lateinit var signatureED25519: String

    fun exampleED25519() {
        exampleCryptoUseCase.exampleED25519()
    }

    fun customSymmetricCrypto() {
        exampleCryptoUseCase.customSymmetricCrypto()
    }

    fun customAsymmetricCrypto() {
        exampleCryptoUseCase.customAsymmetricCrypto()
    }
}