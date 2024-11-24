package com.github.fadlurahmanfdev.core_crypto_example.domain

import android.util.Log
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSAMethod
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoAsymmetricRepository
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoED25519Repository
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoSymmetricRepository

class ExampleCryptoUseCaseImpl(
    private val cryptoAESRepository: CryptoSymmetricRepository,
    private val cryptoED25519Repository: CryptoED25519Repository,
    private val cryptoRSARepository: CryptoAsymmetricRepository,
) : ExampleCryptoUseCase {

    override fun exampleCryptoAES() {
        try {
            val plainText = "Passw0rd!"
            Log.d(this::class.java.simpleName, "plain text: $plainText")
            val key = cryptoAESRepository.generateKey()
            Log.d(this::class.java.simpleName, "key: $key")
            val ivKey = cryptoAESRepository.generateIVKey()
            Log.d(this::class.java.simpleName, "iv key: $ivKey")
            val encryptedText = cryptoAESRepository.encrypt(
                key = key,
                ivKey = ivKey,
                plainText = plainText
            )
            Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")
            val decryptedText = cryptoAESRepository.decrypt(
                key = key,
                ivKey = ivKey,
                encryptedText = encryptedText,
            )
            Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed aes: ${e.message}")
        }
    }

    override fun exampleCryptoRSA() {
        try {
            val plainText = "Passw0rd!"
            Log.d(this::class.java.simpleName, "plain text: $plainText")
            val key = cryptoRSARepository.generateKey()
            Log.d(this::class.java.simpleName, "private key: ${key.privateKey}")
            Log.d(this::class.java.simpleName, "public key: ${key.publicKey}")
            val encryptedText = cryptoRSARepository.encrypt(
                encodedPublicKey = key.publicKey,
                plainText = plainText,
            )
            Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")
            val decryptedText = cryptoRSARepository.decrypt(
                encodedPrivateKey = key.privateKey,
                encryptedText = encryptedText,
            )
            Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
            val signature = cryptoRSARepository.generateSignature(
                privateKey = key.privateKey,
                plainText = plainText,
                signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA1withRSA
            )
            Log.d(this::class.java.simpleName, "signature: $signature")
            val isSignatureVerified = cryptoRSARepository.verifySignature(
                encodedPublicKey = key.publicKey,
                plainText = "Passw0rd!",
                signature = signature,
                signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA1withRSA
            )
            Log.d(this::class.java.simpleName, "is signature verified: $isSignatureVerified")
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed rsa signature: ${e.message}")
        }
    }

    override fun encryptTextWithCombinationRsaAndAes(
        encodedPublicKey: String,
        encodedPrivateKey: String,
        encryptedAESKey: String,
        plainText: String,
        rsaMethod: RSAMethod,
        aesMethod: AESMethod,
    ): String? {
        return null
//        val decryptedAESKey = cryptoRSARepository.decrypt(
//            encodedPrivateKey = encodedPrivateKey,
//            encryptedText = encryptedAESKey,
//            method = rsaMethod
//        )
//        Log.d(this::class.java.simpleName, "decryptedAESKey: $decryptedAESKey")
//        if (decryptedAESKey == null) {
//            Log.d(
//                this::class.java.simpleName,
//                "failed encryptTextWithCombinationRsaAndAes, decryptedAESKey is missing"
//            )
//            return null
//        }
//        return cryptoAESRepository.encrypt(
//            key = decryptedAESKey,
//            ivKey = "",
//            plainText = plainText
//        )
    }

    override fun decryptTextWithCombinationRsaAndAes(
        encodedPrivateKey: String,
        encryptedAESKey: String,
        encryptedText: String,
        rsaMethod: RSAMethod,
        aesMethod: AESMethod,
    ): String? {
        return null
//        val decryptedAESKey = cryptoRSARepository.decrypt(
//            encodedPrivateKey = encodedPrivateKey,
//            encryptedText = encryptedAESKey,
//            method = rsaMethod
//        )
//        Log.d(this::class.java.simpleName, "decryptedAESKey: $decryptedAESKey")
//        if (decryptedAESKey == null) {
//            Log.d(
//                this::class.java.simpleName,
//                "failed decryptTextWithCombinationRsaAndAes, decryptedAESKey is missing"
//            )
//            return null
//        }
//        return cryptoAESRepository.decrypt(
//            key = decryptedAESKey,
//            ivKey = "",
//            encryptedText = encryptedText
//        )
    }

    override fun generateED25519Key(): CryptoKey {
        return cryptoED25519Repository.generateKey()
    }

    override fun generateED25519Signature(
        encodedPrivateKey: String,
        plainText: String,
    ): String? {
        return cryptoED25519Repository.generateSignature(
            privateKey = encodedPrivateKey,
            plainText = plainText,
        )
    }

    override fun verifyED25519Signature() {
        val plainText = "Passw0rd!"
        Log.d(this::class.java.simpleName, "PLAIN TEXT: $plainText")
        val key = cryptoED25519Repository.generateKey()
        Log.d(this::class.java.simpleName, "PRIVATE KEY: ${key.privateKey}")
        Log.d(this::class.java.simpleName, "PUBLIC KEY: ${key.publicKey}")
        val signature = cryptoED25519Repository.generateSignature(
            plainText = plainText,
            privateKey = key.privateKey,
        )
        Log.d(this::class.java.simpleName, "SIGNATURE: $signature")
        if (signature != null) {
            val isSignatureVerified = cryptoED25519Repository.verifySignature(
                plainText = plainText,
                publicKey = key.publicKey,
                signature = signature,
            )
            Log.d(this::class.java.simpleName, "IS SIGNATURE VERIFIED: $isSignatureVerified")
        }
    }

    override fun customSymmetricCrypto() {
//        val isSupported = customSymmetricRepository.isSupported(
//            algorithm = FeatureCryptoAlgorithm.AES,
//            blockMode = FeatureCryptoBlockMode.GCM,
//            padding = FeatureCryptoPadding.NoPadding
//        )
//
//        if (!isSupported){
//            Log.e(this::class.java.simpleName, "no supported of given transformation")
//        }
//
//        val key = customSymmetricRepository.generateKey(FeatureCryptoAlgorithm.AES)
//        Log.d(this::class.java.simpleName, "key: $key")
//        val ivKey = customSymmetricRepository.generateIVKey()
//        Log.d(this::class.java.simpleName, "iv key: $ivKey")
//        val encryptedText = customSymmetricRepository.encrypt(
//            FeatureCryptoAlgorithm.AES,
//            blockMode = FeatureCryptoBlockMode.GCM,
//            padding = FeatureCryptoPadding.NoPadding,
//            encodedKey = key,
//            encodedIVKey = ivKey,
//            plainText = "P4ssword!Sus4h"
//        )
//        Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")
//        val decryptedText = customSymmetricRepository.decrypt(
//            FeatureCryptoAlgorithm.AES,
//            blockMode = FeatureCryptoBlockMode.GCM,
//            padding = FeatureCryptoPadding.NoPadding,
//            encodedKey = key,
//            encodedIVKey = ivKey,
//            encryptedText = encryptedText
//        )
//        Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
    }

    override fun customAsymmetricCrypto() {
//        val isSupported = customAsymmetricRepository.isSupported(
//            algorithm = FeatureCryptoAlgorithm.AES,
//            blockMode = FeatureCryptoBlockMode.GCM,
//            padding = FeatureCryptoPadding.NoPadding
//        )
//
//        if (!isSupported){
//            Log.e(this::class.java.simpleName, "no supported of given transformation")
//        }
//
//        val key = customAsymmetricRepository.generateKey(FeatureCryptoAlgorithm.RSA)
//        Log.d(this::class.java.simpleName, "private key: ${key.privateKey}")
//        Log.d(this::class.java.simpleName, "public key: ${key.publicKey}")
//        val signature = customAsymmetricRepository.generateSignature(
//            privateKey = key.privateKey,
//            plainText = "P4ssword!Sus4h",
//            signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA1withRSA,
//        )
//        Log.d(this::class.java.simpleName, "signature: $signature")
//        val isVerify = customAsymmetricRepository.verifySignature(
//            encodedPublicKey = key.publicKey,
//            algorithm = FeatureCryptoAlgorithm.RSA,
//            plainText = "P4ssword!Sus4h",
//            signature = signature,
//            signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA512withRSA
//        )
//        Log.d(this::class.java.simpleName, "is verify signature: $isVerify")
//        val encryptedText = customAsymmetricRepository.encrypt(
//            algorithm = FeatureCryptoAlgorithm.RSA,
//            blockMode = FeatureCryptoBlockMode.ECB,
//            padding = FeatureCryptoPadding.OAEPWithSHAAndMGF1Padding,
//            encodedPublicKey = key.publicKey,
//            plainText = "P4ssword!Sus4h"
//        )
//        Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")
//        val decryptedText = customAsymmetricRepository.decrypt(
//            algorithm = FeatureCryptoAlgorithm.RSA,
//            blockMode = FeatureCryptoBlockMode.ECB,
//            padding = FeatureCryptoPadding.OAEPWithSHAAndMGF1Padding,
//            encodedPrivateKey = key.privateKey,
//            encryptedText = encryptedText,
//        )
//        Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
    }
}