package com.github.fadlurahmanfdev.core_crypto_example.domain

import android.util.Log
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSAMethod
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSASignatureMethod
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoAESRepository
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoAsymmetricRepository
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoED25519Repository
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoRSARepository
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoSymmetricRepository

class ExampleCryptoUseCaseImpl(
    private val cryptoAESRepository: CryptoAESRepository,
    private val cryptoED25519Repository: CryptoED25519Repository,
    private val cryptoRSARepository: CryptoRSARepository,
    private val customSymmetricRepository: CryptoSymmetricRepository,
    private val customAsymmetricRepository: CryptoAsymmetricRepository,
) : ExampleCryptoUseCase {

    override fun encryptDecryptAES() {
        val plainText = "Passw0rd!"
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "PLAIN TEXT: $plainText")
        val key = cryptoAESRepository.generateKey()
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "AES KEY: $key")
        val ivKey = cryptoAESRepository.generateIVKey()
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "IV KEY: $ivKey")
        val encryptedText = cryptoAESRepository.encrypt(
            key = key,
            plainText = plainText,
            ivKey = ivKey
        )
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "ENCRYPTED TEXT: $encryptedText")
        if (encryptedText != null) {
            val decryptedText = cryptoAESRepository.decrypt(
                key = key,
                encryptedText = encryptedText,
                ivKey = ivKey,
            )
            Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "DECRYPTED TEXT: $decryptedText")
        }
    }

    override fun secureEncryptDecryptAES() {
        val plainText = "Passw0rd!"
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "PLAIN TEXT: $plainText")
        val key = cryptoAESRepository.generateSecureKey()
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "AES KEY: $key")
        val encryptedText = cryptoAESRepository.encrypt(
            key = key,
            ivKey = "",
            plainText = plainText,
        )
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "ENCRYPTED TEXT: $encryptedText")
        if (encryptedText != null) {
            val decryptedText = cryptoAESRepository.decrypt(
                key = key,
                ivKey = "",
                encryptedText = encryptedText,
            )
            Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "DECRYPTED TEXT: $decryptedText")
        }
    }

    override fun encryptDecryptRSA() {
        val plainText = "Passw0rd!"
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "PLAIN TEXT: $plainText")
        val key = cryptoRSARepository.generateKey()
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "PRIVATE KEY: ${key.privateKey}")
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "PUBLIC KEY: ${key.publicKey}")
        val encryptedText = cryptoRSARepository.encrypt(
            encodedPublicKey = key.publicKey,
            plainText = plainText,
            method = RSAMethod.RSA_ECB_PKCS1Padding
        )
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "ENCRYPTED TEXT: $encryptedText")
        if (encryptedText != null) {
            val decryptedText = cryptoRSARepository.decrypt(
                key.privateKey,
                encryptedText = encryptedText,
                method = RSAMethod.RSA_ECB_PKCS1Padding,
            )
            Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "DECRYPTED TEXT: $decryptedText")

            val signature = cryptoRSARepository.generateSignature(
                encodedPrivateKey = key.privateKey,
                plainText = plainText,
                method = RSASignatureMethod.SHA256withRSA,
            )
            Log.d(
                ExampleCryptoUseCaseImpl::class.java.simpleName,
                "SIGNATURE: $signature"
            )
            if (signature != null) {
                val isSignatureVerified = cryptoRSARepository.verifySignature(
                    encodedPublicKey = key.publicKey,
                    plainText = "Passw0rd!",
                    signature = signature,
                    method = RSASignatureMethod.SHA256withRSA,
                )
                Log.d(
                    ExampleCryptoUseCaseImpl::class.java.simpleName,
                    "IS SIGNATURE VERIFIED: $isSignatureVerified"
                )
            }
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
            key = decryptedAESKey,
            plainText = plainText,
            method = aesMethod,
            ivKey = ""
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
            key = decryptedAESKey,
            method = aesMethod,
            ivKey = ""
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
            privateKey = encodedPrivateKey,
            plainText = plainText,
        )
    }

    override fun verifyED25519Signature() {
        val plainText = "Passw0rd!"
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "PLAIN TEXT: $plainText")
        val key = cryptoED25519Repository.generateKey()
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "PRIVATE KEY: ${key.privateKey}")
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "PUBLIC KEY: ${key.publicKey}")
        val signature = cryptoED25519Repository.generateSignature(
            plainText = plainText,
            privateKey = key.privateKey,
        )
        Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "SIGNATURE: $signature")
        if (signature != null) {
            val isSignatureVerified = cryptoED25519Repository.verifySignature(
                plainText = plainText,
                publicKey = key.publicKey,
                signature = signature,
            )
            Log.d(ExampleCryptoUseCaseImpl::class.java.simpleName, "IS SIGNATURE VERIFIED: $isSignatureVerified")
        }
    }

    override fun customSymmetricCrypto() {
        val isSupported = customSymmetricRepository.isSupported(
            algorithm = FeatureCryptoAlgorithm.AES,
            blockMode = FeatureCryptoBlockMode.GCM,
            padding = FeatureCryptoPadding.NoPadding
        )

        if (!isSupported){
            Log.e(this::class.java.simpleName, "no supported of given transformation")
        }

        val key = customSymmetricRepository.generateKey(FeatureCryptoAlgorithm.AES)
        Log.d(this::class.java.simpleName, "key: $key")
        val ivKey = customSymmetricRepository.generateIVKey()
        Log.d(this::class.java.simpleName, "iv key: $ivKey")
        val encryptedText = customSymmetricRepository.encrypt(
            FeatureCryptoAlgorithm.AES,
            blockMode = FeatureCryptoBlockMode.GCM,
            padding = FeatureCryptoPadding.NoPadding,
            encodedKey = key,
            encodedIVKey = ivKey,
            plainText = "P4ssword!Sus4h"
        )
        Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")
        val decryptedText = customSymmetricRepository.decrypt(
            FeatureCryptoAlgorithm.AES,
            blockMode = FeatureCryptoBlockMode.GCM,
            padding = FeatureCryptoPadding.NoPadding,
            encodedKey = key,
            encodedIVKey = ivKey,
            encryptedText = encryptedText
        )
        Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
    }

    override fun customAsymmetricCrypto() {
        val isSupported = customAsymmetricRepository.isSupported(
            algorithm = FeatureCryptoAlgorithm.AES,
            blockMode = FeatureCryptoBlockMode.GCM,
            padding = FeatureCryptoPadding.NoPadding
        )

        if (!isSupported){
            Log.e(this::class.java.simpleName, "no supported of given transformation")
        }

        val key = customAsymmetricRepository.generateKey(FeatureCryptoAlgorithm.RSA)
        Log.d(this::class.java.simpleName, "private key: ${key.privateKey}")
        Log.d(this::class.java.simpleName, "public key: ${key.publicKey}")
        val signature = customAsymmetricRepository.generateSignature(
            encodedPrivateKey = key.privateKey,
            algorithm = FeatureCryptoAlgorithm.RSA,
            signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA1withRSA,
            plainText = "P4ssword!Sus4h",
        )
        Log.d(this::class.java.simpleName, "signature: $signature")
        val isVerify = customAsymmetricRepository.verifySignature(
            encodedPublicKey = key.publicKey,
            algorithm = FeatureCryptoAlgorithm.RSA,
            plainText = "P4ssword!Sus4h",
            signature = signature,
            signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA512withRSA
        )
        Log.d(this::class.java.simpleName, "is verify signature: $isVerify")
        val encryptedText = customAsymmetricRepository.encrypt(
            algorithm = FeatureCryptoAlgorithm.RSA,
            blockMode = FeatureCryptoBlockMode.ECB,
            padding = FeatureCryptoPadding.OAEPWithSHAAndMGF1Padding,
            encodedPublicKey = key.publicKey,
            plainText = "P4ssword!Sus4h"
        )
        Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")
        val decryptedText = customAsymmetricRepository.decrypt(
            algorithm = FeatureCryptoAlgorithm.RSA,
            blockMode = FeatureCryptoBlockMode.ECB,
            padding = FeatureCryptoPadding.OAEPWithSHAAndMGF1Padding,
            encodedPrivateKey = key.privateKey,
            encryptedText = encryptedText,
        )
        Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
    }
}