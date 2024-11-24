package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import android.util.Log
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey
import com.fadlurahmanfdev.kotlin_core_crypto.others.BaseCrypto
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

abstract class BaseAsymmetricCrypto : BaseCrypto() {
    fun generateKey(algorithm: FeatureCryptoAlgorithm): CryptoKey {
        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm.name)
        val key = keyPairGenerator.generateKeyPair()
        return CryptoKey(
            privateKey = encode(key.private.encoded),
            publicKey = encode(key.public.encoded)
        )
    }

    fun generateSignature(
        privateKey: String,
        plainText: String,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm,
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(decode(privateKey))
        val privateKeyInstance = KeyFactory.getInstance(FeatureCryptoAlgorithm.RSA.name).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm.name)
        signer.initSign(privateKeyInstance)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
    }

    fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        algorithm: FeatureCryptoAlgorithm,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm
    ): Boolean {
        return try {
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance(algorithm.name).generatePublic(publicKeySpec)
            val signer = Signature.getInstance(signatureAlgorithm.name)
            signer.initVerify(publicKey)
            signer.update(plainText.toByteArray())
            signer.verify(decode(signature))
            true
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed verifySignature: ${e.message}")
            false
        }
    }

    fun encrypt(
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        encodedPublicKey: String,
        plainText: String,
    ): String {
        val cipher = Cipher.getInstance("${algorithm.name}/${blockMode.value}/${padding.value}")
        val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
        val publicKey = KeyFactory.getInstance(algorithm.name).generatePublic(publicKeySpec)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedByteArray = cipher.doFinal(plainText.toByteArray())
        return encode(encryptedByteArray)
    }

    fun decrypt(
        algorithm: FeatureCryptoAlgorithm,
        blockMode: FeatureCryptoBlockMode,
        padding: FeatureCryptoPadding,
        encodedPrivateKey: String,
        encryptedText: String,
    ): String {
        val cipher = Cipher.getInstance("${algorithm.name}/${blockMode.value}/${padding.value}")
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(algorithm.name).generatePrivate(privateKeySpec)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}