package com.github.fadlurahmanfdev.core_crypto_example.domain

import android.util.Log
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSAMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSASignatureMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoAESRepository
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoED25519Repository
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoRSARepository

class ExampleCryptoUseCaseImpl(
    private val cryptoAESRepository: CryptoAESRepository,
    private val cryptoED25519Repository: CryptoED25519Repository,
    private val cryptoRSARepository: CryptoRSARepository,
) : ExampleCryptoUseCase {
    override fun generateAESKey(): String {
        return cryptoAESRepository.generateKey()
    }

    override fun encryptAES(encodedKey: String, plainText: String, method: AESMethod): String? {
        return cryptoAESRepository.encrypt(
            encodedKey = encodedKey,
            plainText = plainText,
            method = method
        )
    }

    override fun decryptAES(encodedKey: String, encryptedText: String, method: AESMethod): String? {
        return cryptoAESRepository.decrypt(
            encodedKey = encodedKey,
            encryptedText = encryptedText,
            method = method
        )
    }

    override fun generateRSAKey(): CryptoKey {
        return cryptoRSARepository.generateKey()
    }

    override fun encryptRSA(
        encodedPublicKey: String,
        plainText: String,
        method: RSAMethod
    ): String? {
        return cryptoRSARepository.encrypt(
            encodedPublicKey = encodedPublicKey,
            plainText = plainText,
            method = method
        )
    }

    override fun decryptRSA(
        encodedPrivateKey: String,
        encryptedText: String,
        method: RSAMethod
    ): String? {
        return cryptoRSARepository.decrypt(
            encodedPrivateKey = encodedPrivateKey,
            encryptedText = encryptedText,
            method = method
        )
    }

    override fun generateRSASignature(
        encodedPrivateKey: String,
        plainText: String,
        method: RSASignatureMethod,
    ): String? {
        return cryptoRSARepository.generateSignature(
            encodedPrivateKey = encodedPrivateKey,
            plainText = plainText,
            method = method
        )
    }

    override fun verifyRSASignature(
        encodedPublicKey: String,
        encodedSignature: String,
        plainText: String,
        method: RSASignatureMethod,
    ): Boolean {
        return cryptoRSARepository.verifySignature(
            encodedPublicKey = encodedPublicKey,
            encodedSignature = encodedSignature,
            plainText = plainText,
            method = method
        )
    }

    override fun encryptTextWithCombinationRsaAndAes(
        encodedPublicKey: String,
        encodedPrivateKey: String,
        encryptedAESKey: String,
        plainText: String,
        rsaMethod: RSAMethod,
        aesMethod: AESMethod,
    ): String? {
        val decryptedAESKey = cryptoRSARepository.decrypt(
            encodedPrivateKey = encodedPrivateKey,
            encryptedText = encryptedAESKey,
            method = rsaMethod
        )
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "decryptedAESKey: $decryptedAESKey")
        if (decryptedAESKey == null) {
            Log.d(
                ExampleCryptoUseCaseImpl::class.java.simpleName,
                "failed encryptTextWithCombinationRsaAndAes, decryptedAESKey is missing"
            )
            return null
        }
        return cryptoAESRepository.encrypt(
            encodedKey = decryptedAESKey,
            plainText = plainText,
            method = aesMethod
        )
    }

    override fun decryptTextWithCombinationRsaAndAes(
        encodedPrivateKey: String,
        encryptedAESKey: String,
        encryptedText: String,
        rsaMethod: RSAMethod,
        aesMethod: AESMethod,
    ): String? {
        val decryptedAESKey = cryptoRSARepository.decrypt(
            encodedPrivateKey = encodedPrivateKey,
            encryptedText = encryptedAESKey,
            method = rsaMethod
        )
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "decryptedAESKey: $decryptedAESKey")
        if (decryptedAESKey == null) {
            Log.d(
                ExampleCryptoUseCaseImpl::class.java.simpleName,
                "failed decryptTextWithCombinationRsaAndAes, decryptedAESKey is missing"
            )
            return null
        }
        return cryptoAESRepository.decrypt(
            encryptedText = encryptedText,
            encodedKey = decryptedAESKey,
            method = aesMethod,
        )
    }

    override fun generateED25519Key(): CryptoKey {
        return cryptoED25519Repository.generateKey()
    }

    override fun generateED25519Signature(
        encodedPrivateKey: String,
        plainText: String,
    ): String? {
        return cryptoED25519Repository.generateSignature(
            encodedPrivateKey = encodedPrivateKey,
            plainText = plainText,
        )
    }

    override fun verifyED25519Signature(
        encodedPublicKey: String,
        encodedSignature: String,
        plainText: String,
    ): Boolean {
        return cryptoED25519Repository.verifySignature(
            encodedPublicKey = encodedPublicKey,
            signature = encodedSignature,
            text = plainText
        )
    }

}