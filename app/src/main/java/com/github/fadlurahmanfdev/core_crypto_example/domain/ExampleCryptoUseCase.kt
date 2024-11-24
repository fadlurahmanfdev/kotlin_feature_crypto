package com.github.fadlurahmanfdev.core_crypto_example.domain

import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSAMethod
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey


interface ExampleCryptoUseCase {
    fun exampleCryptoAES()
    fun exampleCryptoRSA()

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

    fun generateED25519Key(): CryptoKey

    fun generateED25519Signature(
        encodedPrivateKey: String,
        plainText: String,
    ): String?

    fun verifyED25519Signature()

    fun customSymmetricCrypto()

    fun customAsymmetricCrypto()
}