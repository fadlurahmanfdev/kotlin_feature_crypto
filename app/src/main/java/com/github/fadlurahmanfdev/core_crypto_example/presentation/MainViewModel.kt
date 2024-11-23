package com.github.fadlurahmanfdev.core_crypto_example.presentation

import androidx.lifecycle.ViewModel
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey
import com.github.fadlurahmanfdev.core_crypto_example.domain.ExampleCryptoUseCase

class MainViewModel(
    private val exampleCryptoUseCase: ExampleCryptoUseCase
) : ViewModel() {

    // AES
    private lateinit var encodedAESKey: String
    private lateinit var encryptedAESText: String

    // RSA
    private lateinit var rsaKey: CryptoKey
    private lateinit var encryptedAESKey: String
    private lateinit var encryptedRSAText: String
    private lateinit var signatureRSA: String

    // ED25519
    private lateinit var ed25519Key: CryptoKey
    private lateinit var signatureED25519: String

    fun encryptDecryptAES() {
        exampleCryptoUseCase.encryptDecryptAES()
        println("-------------------------------------")
        exampleCryptoUseCase.secureEncryptDecryptAES()
    }

    fun encryptDecryptRSA() {
        exampleCryptoUseCase.encryptDecryptRSA()
    }

    fun verifyED25519Signature() {
        exampleCryptoUseCase.verifyED25519Signature()
    }

    fun customSymmetricCrypto() {
        exampleCryptoUseCase.customSymmetricCrypto()
    }

    fun customAsymmetricCrypto() {
        exampleCryptoUseCase.customAsymmetricCrypto()
    }
}