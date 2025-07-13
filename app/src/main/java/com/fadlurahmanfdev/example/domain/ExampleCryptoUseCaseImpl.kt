package com.fadlurahmanfdev.example.domain

import android.util.Log
import com.fadlurahmanfdev.kotlin_feature_crypto.CryptoVaultED25519
import com.fadlurahmanfdev.kotlin_feature_crypto.CryptoVaultCustomKeyVault
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultBlockMode
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultPadding
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.data.model.CryptoVaultKey

class ExampleCryptoUseCaseImpl(
    private val cryptoED25519Repository: CryptoVaultED25519,
    private val cryptoVaultCustomSymmetric: CryptoVaultCustomKeyVault,
) : ExampleCryptoUseCase {

    override fun generateED25519Key(): CryptoVaultKey {
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

    override fun customSymmetricCrypto() {
        val plainText = "P4ssw0rd!Sus4h!B9t"
        val transformation = "${com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm.ChaCha20}/${com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultBlockMode.Poly1305}/${com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultPadding.NoPadding}"
        val isSupported = cryptoVaultCustomSymmetric.isSupported(
            transformation = transformation
        )

        if (!isSupported) {
            Log.e(
                this::class.java.simpleName,
                "no supported of given transformation: $transformation"
            )
            return
        }

        val key = cryptoVaultCustomSymmetric.generateKey(com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm.ChaCha20)
        val ivKey = ""
//        Log.d(this::class.java.simpleName, "key: $key")
//        val encryptedText = cryptoVaultCustomSymmetric.encrypt(
//            transformation = transformation,
//            algorithm = com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm.ChaCha20,
//            plainText = plainText,
//            encodedKey = key,
//            ivKey = ivKey
//        )
//        Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")
//        val decryptedText = cryptoVaultCustomSymmetric.decrypt(
//            algorithm = com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm.ChaCha20,
//            transformation = transformation,
//            encryptedText = encryptedText,
//            key = key,
//            ivKey = ivKey
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