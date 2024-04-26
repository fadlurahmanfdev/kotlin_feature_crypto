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

    fun generateAESKey() {
        val key = exampleCryptoUseCase.generateAESKey()
        encodedAESKey = key
        Log.d(MainViewModel::class.java.simpleName, "AES KEY: $key")
    }

    fun encryptAES() {
        val encrypted = exampleCryptoUseCase.encryptAES(
            encodedKey = encodedAESKey,
            plainText = "TES_VALUE_AES",
            method = AESMethod.AES_GCM_NoPadding
        )
        Log.d(MainViewModel::class.java.simpleName, "ENCRYPTED AES: $encrypted")
        if (encrypted != null) {
            encryptedAESText = encrypted
        }
    }

    fun decryptAES() {
        val decrypted = exampleCryptoUseCase.decryptAES(
            encodedKey = encodedAESKey,
            encryptedText = encryptedAESText,
            method = AESMethod.AES_GCM_NoPadding
        )
        Log.d(MainViewModel::class.java.simpleName, "DECRYPTED AES: $decrypted")
    }

    fun generateRSAKey() {
        rsaKey = exampleCryptoUseCase.generateRSAKey()
        encodedAESKey = exampleCryptoUseCase.generateAESKey()
        Log.d(
            MainViewModel::class.java.simpleName, "RSA KEY:\n" +
                    "PRIVATE KEY: ${rsaKey.privateKey}" +
                    "\n\n" +
                    "-------------------------" +
                    "\n\n" +
                    "PUBLIC KEY: ${rsaKey.publicKey}" +
                    "\n\n" +
                    "AES KEY: $encodedAESKey"
        )

        val encryptedAESKey = exampleCryptoUseCase.encryptRSA(
            encodedPublicKey = rsaKey.publicKey,
            plainText = encodedAESKey,
            method = RSAMethod.RSA_ECB_PKCS1Padding,
        )
        Log.d(MainViewModel::class.java.simpleName, "ENCRYPTED AES KEY: $encryptedAESKey")
        if (encryptedAESKey != null) {
            this.encryptedAESKey = encryptedAESKey
        }
    }

    fun encryptRSA() {
        val encrypted = exampleCryptoUseCase.encryptTextWithCombinationRsaAndAes(
            encodedPublicKey = rsaKey.publicKey,
            encodedPrivateKey = rsaKey.privateKey,
            encryptedAESKey = encryptedAESKey,
            plainText = "TES_VALUE_RSA",
            rsaMethod = RSAMethod.RSA_ECB_PKCS1Padding,
            aesMethod = AESMethod.AES_GCM_NoPadding,
        )
        Log.d(MainViewModel::class.java.simpleName, "ENCRYPTED RSA: $encrypted")
        if (encrypted != null) {
            encryptedRSAText = encrypted
        }
    }

    fun decryptRSA() {
        val decrypted = exampleCryptoUseCase.decryptTextWithCombinationRsaAndAes(
            encodedPrivateKey = rsaKey.privateKey,
            encryptedAESKey = encryptedAESKey,
            encryptedText = encryptedRSAText,
            rsaMethod = RSAMethod.RSA_ECB_PKCS1Padding,
            aesMethod = AESMethod.AES_GCM_NoPadding
        )
        Log.d(MainViewModel::class.java.simpleName, "DECRYPTED RSA: $decrypted")
    }

    fun generateRSASignature() {
        val signature = exampleCryptoUseCase.generateRSASignature(
            encodedPrivateKey = rsaKey.privateKey,
            plainText = "TES_SIGNATURE_RSA",
            method = RSASignatureMethod.MD5withRSA
        )
        Log.d(MainViewModel::class.java.simpleName, "SIGNATURE RSA: $signature")
        if (signature != null) {
            signatureRSA = signature
        }
    }

    fun verifyAESSignature() {
        val decrypted = exampleCryptoUseCase.verifyRSASignature(
            encodedPublicKey = rsaKey.publicKey,
            encodedSignature = rsaKey.privateKey,
            plainText = "TES_SIGNATURE_RSA",
            method = RSASignatureMethod.MD5withRSA,
        )
        Log.d(MainViewModel::class.java.simpleName, "DECRYPTED RSA: $decrypted")
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