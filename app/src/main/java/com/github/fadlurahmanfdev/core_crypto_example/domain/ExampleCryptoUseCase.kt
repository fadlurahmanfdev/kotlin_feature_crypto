package com.github.fadlurahmanfdev.core_crypto_example.domain

import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSAMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSASignatureMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey

interface ExampleCryptoUseCase {
    fun generateAESKey(): String
    fun encryptAES(encodedKey: String, plainText: String, method: AESMethod): String?
    fun decryptAES(encodedKey: String, encryptedText: String, method: AESMethod): String?
    fun generateRSAKey(): CryptoKey
    fun encryptRSA(
        encodedPublicKey: String,
        plainText: String,
        method: RSAMethod,
    ): String?

    fun decryptRSA(
        encodedPrivateKey: String,
        encryptedText: String,
        method: RSAMethod
    ): String?

    fun generateRSASignature(
        encodedPrivateKey: String,
        plainText: String,
        method: RSASignatureMethod,
    ): String?

    fun verifyRSASignature(
        encodedPublicKey: String,
        encodedSignature: String,
        plainText: String,
        method: RSASignatureMethod,
    ): Boolean

    fun encryptTextWithCombinationRsaAndAes(
        encodedPublicKey: String,
        encodedPrivateKey: String,
        encryptedAESKey: String,
        plainText: String,
        rsaMethod: RSAMethod,
        aesMethod: AESMethod,
    ): String?

    fun decryptTextWithCombinationRsaAndAes(
        encodedPrivateKey: String,
        encryptedAESKey: String,
        encryptedText: String,
        rsaMethod: RSAMethod,
        aesMethod: AESMethod,
    ): String?

    fun generateED25519Key():CryptoKey

    fun generateED25519Signature(
        encodedPrivateKey: String,
        plainText: String,
    ): String?

    fun verifyED25519Signature(
        encodedPublicKey: String,
        encodedSignature: String,
        plainText: String,
    ): Boolean
}