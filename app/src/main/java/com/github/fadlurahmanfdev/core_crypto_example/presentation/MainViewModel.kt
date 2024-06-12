package com.github.fadlurahmanfdev.core_crypto_example.presentation

import android.util.Log
import androidx.lifecycle.ViewModel
import com.github.fadlurahmanfdev.core_crypto_example.domain.ExampleCryptoUseCase
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSAMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSASignatureMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey

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
    }

    fun encryptDecryptRSA() {
        exampleCryptoUseCase.encryptDecryptRSA()
    }

    fun generateED25519Key() {
        ed25519Key = exampleCryptoUseCase.generateED25519Key()
        Log.d(
            MainViewModel::class.java.simpleName, "ED25519 KEY:\n" +
                    "PRIVATE KEY: ${ed25519Key.privateKey}" +
                    "\n\n" +
                    "-------------------------" +
                    "\n\n" +
                    "PUBLIC KEY: ${ed25519Key.publicKey}"
        )
    }

    fun generateED25519Signature() {
        val signature = exampleCryptoUseCase.generateED25519Signature(
            encodedPrivateKey = ed25519Key.privateKey,
            plainText = "TES_SIGNATURE_ED25519",
        )
        Log.d(MainViewModel::class.java.simpleName, "SIGNATURE ED25519: $signature")
        if (signature != null) {
            signatureED25519 = signature
        }
    }

    fun verifyED25519Signature() {
        val decrypted = exampleCryptoUseCase.verifyED25519Signature(
            encodedPublicKey = ed25519Key.publicKey,
            encodedSignature = signatureED25519,
            plainText = "TES_SIGNATURE_ED25519",
        )
        Log.d(MainViewModel::class.java.simpleName, "DECRYPTED ED25519: $decrypted")
    }
}