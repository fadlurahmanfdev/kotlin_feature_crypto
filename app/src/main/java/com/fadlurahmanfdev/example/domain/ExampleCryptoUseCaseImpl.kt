package com.fadlurahmanfdev.example.domain

import android.util.Log
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.data.impl_repositories.CryptoAESRepositoryImpl
import com.fadlurahmanfdev.kotlin_feature_crypto.data.impl_repositories.CryptoDynamicSymmetricRepositoryImpl
import com.fadlurahmanfdev.kotlin_feature_crypto.data.model.CryptoKey
import com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories.CryptoAESRepository
import com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories.CryptoECRepository
import com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories.CryptoED25519Repository
import com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories.CryptoRSARepository

class ExampleCryptoUseCaseImpl(
    private val cryptoAESRepository: CryptoAESRepository,
    private val cryptoED25519Repository: CryptoED25519Repository,
    private val cryptoRSARepository: CryptoRSARepository,
    private val cryptoECRepository: CryptoECRepository,
    private val cryptoDynamicSymmetricRepositoryImpl: CryptoDynamicSymmetricRepositoryImpl,
) : ExampleCryptoUseCase {

    override fun exampleCryptoAES() {
        try {
            Log.d(this::class.java.simpleName, "example AES")
            val plainText = "Passw0rd!Sus4h"
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
            Log.d(this::class.java.simpleName, "example RSA")
            val plainText = "Passw0rd!Sus4hB9t"
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
                encodedPrivateKey = key.privateKey,
                plainText = plainText,
                signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA256withRSA
            )
            Log.d(this::class.java.simpleName, "signature: $signature")
            val isSignatureVerified = cryptoRSARepository.verifySignature(
                encodedPublicKey = key.publicKey,
                plainText = "Passw0rd!",
                signature = signature,
                signatureAlgorithm = FeatureCryptoSignatureAlgorithm.MD5withRSA
            )
            Log.d(this::class.java.simpleName, "is signature verified: $isSignatureVerified")
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed rsa signature: ${e.message}")
        }
    }

    override fun exampleCombineRSAAndAES() {
        try {
            Log.d(this::class.java.simpleName, "example combine RSA & AES")
            val rsaKey = cryptoRSARepository.generateKey()
            Log.d(this::class.java.simpleName, "rsa private key: ${rsaKey.privateKey}")
            Log.d(this::class.java.simpleName, "rsa public key: ${rsaKey.publicKey}")

            val plainText = "Passw0rd!Sus4hB9t"

            Log.d(this::class.java.simpleName, "plain text: $plainText")
            val aesKey = cryptoAESRepository.generateKey()
            Log.d(this::class.java.simpleName, "aes key: $aesKey")
            val aesIVKey = cryptoAESRepository.generateIVKey()
            Log.d(this::class.java.simpleName, "aes iv key: $aesIVKey")

            val encryptedText = cryptoAESRepository.encrypt(
                key = aesKey,
                ivKey = aesIVKey,
                plainText = plainText
            )
            Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")

            val encryptedAESKey = cryptoRSARepository.encrypt(
                encodedPublicKey = rsaKey.publicKey,
                plainText = aesKey
            )
            Log.d(this::class.java.simpleName, "encrypted aes key: $encryptedAESKey")
            val encryptedAESIVKey = cryptoRSARepository.encrypt(
                encodedPublicKey = rsaKey.publicKey,
                plainText = aesIVKey
            )
            Log.d(this::class.java.simpleName, "encrypted aes iv key: $encryptedAESIVKey")

            val decryptedAESKey = cryptoRSARepository.decrypt(
                encodedPrivateKey = rsaKey.privateKey,
                encryptedText = encryptedAESKey,
            )
            Log.d(this::class.java.simpleName, "decrypted aes key: $decryptedAESKey")

            val decryptedAESIVKey = cryptoRSARepository.decrypt(
                encodedPrivateKey = rsaKey.privateKey,
                encryptedText = encryptedAESIVKey,
            )
            Log.d(this::class.java.simpleName, "decrypted aes iv key: $decryptedAESIVKey")

            val decryptedText = cryptoAESRepository.decrypt(
                key = decryptedAESKey,
                ivKey = decryptedAESIVKey,
                encryptedText = encryptedText
            )
            Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed combine rsa & aes: ${e.message}")
        }
    }

    override fun generateED25519Key(): CryptoKey {
        return cryptoED25519Repository.generateKey()
    }

    override fun generateED25519Signature(
        encodedPrivateKey: String,
        plainText: String,
    ): String {
        return cryptoED25519Repository.generateSignature(
            encodedPrivateKey = encodedPrivateKey,
            plainText = plainText,
        )
    }

    override fun exampleED25519() {
        Log.d(this::class.java.simpleName, "example ED25519")
        val plainText = "Passw0rd!Sus4hB9t"
        Log.d(this::class.java.simpleName, "plain text: $plainText")
        val key = cryptoED25519Repository.generateKey()
        Log.d(this::class.java.simpleName, "private key: ${key.privateKey}")
        Log.d(this::class.java.simpleName, "public key: ${key.publicKey}")
        val signature = cryptoED25519Repository.generateSignature(
            plainText = plainText,
            encodedPrivateKey = key.privateKey,
        )
        Log.d(this::class.java.simpleName, "signature: $signature")
        val isVerified = cryptoED25519Repository.verifySignature(
            plainText = plainText,
            encodedPublicKey = key.publicKey,
            signature = signature,
        )
        Log.d(this::class.java.simpleName, "is signature verified: $isVerified")
    }

    override fun exampleECKeyExchange() {
        Log.d(this::class.java.simpleName, "example EC Key Exchange")
        val aliceKey = cryptoECRepository.generateKey()
        Log.d(this::class.java.simpleName, "alice private key: ${aliceKey.privateKey}")
        Log.d(this::class.java.simpleName, "alice public key: ${aliceKey.publicKey}")
        val bobKey = cryptoECRepository.generateKey()
        Log.d(this::class.java.simpleName, "bob private key: ${bobKey.privateKey}")
        Log.d(this::class.java.simpleName, "bob public key: ${bobKey.publicKey}")

        val aliceSharedSecret = cryptoECRepository.generateSharedSecret(
            ourEncodedPrivateKey = aliceKey.privateKey,
            otherEncodedPublicKey = bobKey.publicKey
        )
        Log.d(this::class.java.simpleName, "alice shared secret: $aliceSharedSecret")
        val bobSharedSecret = cryptoECRepository.generateSharedSecret(
            ourEncodedPrivateKey = bobKey.privateKey,
            otherEncodedPublicKey = aliceKey.publicKey
        )
        Log.d(this::class.java.simpleName, "bob shared secret: $bobSharedSecret")

        val plainText = "P4ssw0rd!Sus4hB9t"
        val keyFromAliceSharedSecret = cryptoECRepository.derivedSharedSecret(aliceSharedSecret)
        Log.d(
            this::class.java.simpleName,
            "key from alice shared secret: $keyFromAliceSharedSecret"
        )

        val cryptoAESRepositoryImpl = CryptoAESRepositoryImpl()
        val aesIvKey = cryptoAESRepositoryImpl.generateIVKey()
        Log.d(this::class.java.simpleName, "aes iv key: $aesIvKey")

        Log.d(this::class.java.simpleName, "plain text: $plainText")
        val encryptedText = cryptoAESRepositoryImpl.encrypt(
            key = keyFromAliceSharedSecret,
            ivKey = aesIvKey,
            plainText = plainText,
        )
        Log.d(this::class.java.simpleName, "encrypted text via alice: $encryptedText")

        val keyFromBobSharedSecret = cryptoECRepository.derivedSharedSecret(bobSharedSecret)
        Log.d(this::class.java.simpleName, "key from bob shared secret: $keyFromBobSharedSecret")
        val decryptedText = cryptoAESRepository.decrypt(
            key = keyFromBobSharedSecret,
            ivKey = aesIvKey,
            encryptedText = encryptedText
        )
        Log.d(this::class.java.simpleName, "decrypted text via bob: $decryptedText")
    }

    override fun exampleEC() {
        try {
            Log.d(this::class.java.simpleName, "example EC")
            val plainText = "P4ssw0rd!Sus4h!Bgt"
            val key = cryptoECRepository.generateKey()

            Log.d(this::class.java.simpleName, "public key: ${key.publicKey}")
            Log.d(this::class.java.simpleName, "private key: ${key.privateKey}")

            val signature = cryptoECRepository.generateSignature(
                encodedPrivateKey = key.privateKey,
                plainText = plainText,
                signatureAlgorithm = FeatureCryptoSignatureAlgorithm.ECDSA,
            )
            Log.d(this::class.java.simpleName, "signature: $signature")
            val isVerified = cryptoECRepository.verifySignature(
                encodedPublicKey = key.publicKey,
                signature = signature,
                plainText = plainText,
                signatureAlgorithm = FeatureCryptoSignatureAlgorithm.ECDSA,
            )
            Log.d(this::class.java.simpleName, "is verified: $isVerified")
        } catch (e: Throwable) {
            Log.d(this::class.java.simpleName, "failed ec: ${e.message}")
        }
    }

    override fun customSymmetricCrypto() {
        val plainText = "P4ssw0rd!Sus4h!B9t"
        val transformation = "${FeatureCryptoAlgorithm.ChaCha20}/${FeatureCryptoBlockMode.Poly1305}/${FeatureCryptoPadding.NoPadding}"
        val isSupported = cryptoDynamicSymmetricRepositoryImpl.isSupported(
            transformation = transformation
        )

        if (!isSupported) {
            Log.e(
                this::class.java.simpleName,
                "no supported of given transformation: $transformation"
            )
            return
        }

        val key = cryptoDynamicSymmetricRepositoryImpl.generateKey(FeatureCryptoAlgorithm.ChaCha20)
        val ivKey = cryptoDynamicSymmetricRepositoryImpl.generateIVKey(12)
        Log.d(this::class.java.simpleName, "key: $key")
        val encryptedText = cryptoDynamicSymmetricRepositoryImpl.encrypt(
            transformation = transformation,
            algorithm = FeatureCryptoAlgorithm.ChaCha20,
            plainText = plainText,
            key = key,
            ivKey = ivKey
        )
        Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")
        val decryptedText = cryptoDynamicSymmetricRepositoryImpl.decrypt(
            algorithm = FeatureCryptoAlgorithm.ChaCha20,
            transformation = transformation,
            encryptedText = encryptedText,
            key = key,
            ivKey = ivKey
        )
        Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
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