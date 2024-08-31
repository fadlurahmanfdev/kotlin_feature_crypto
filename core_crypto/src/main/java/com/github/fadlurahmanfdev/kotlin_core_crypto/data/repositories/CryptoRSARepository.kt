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
        /**
         * encoded public key, get from generateKey().publicKey
         * @see CryptoRSARepository.generateKey
         * */
        publicKey: String,
        plainText: String,
        method: RSAMethod = RSAMethod.RSA_ECB_PKCS1Padding,
    ): String?

    fun decrypt(
        /**
         * encoded private key, get from generateKey().privateKey
         * @see CryptoRSARepository.generateKey
         * */
        privateKey: String,
        encryptedText: String,
        method: RSAMethod = RSAMethod.RSA_ECB_PKCS1Padding,
    ): String?
}