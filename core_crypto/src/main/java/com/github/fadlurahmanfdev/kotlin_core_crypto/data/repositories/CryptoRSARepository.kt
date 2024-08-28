package com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSAMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSASignatureMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey

interface CryptoRSARepository {
    fun generateKey(): CryptoKey
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        method: RSASignatureMethod
    ): String?

    fun verifySignature(
        encodedPublicKey: String,
        encodedSignature: String,
        plainText: String,
        method: RSASignatureMethod,
    ): Boolean

    fun encrypt(
        encodedPublicKey: String,
        plainText: String,
        method: RSAMethod = RSAMethod.RSA_ECB_PKCS1Padding,
    ): String?

    fun decrypt(
        encodedPrivateKey: String, encryptedText: String,
        method: RSAMethod = RSAMethod.RSA_ECB_PKCS1Padding,
    ): String?
}