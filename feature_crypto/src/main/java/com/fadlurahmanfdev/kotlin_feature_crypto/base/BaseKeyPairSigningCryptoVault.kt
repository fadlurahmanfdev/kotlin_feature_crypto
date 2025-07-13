package com.fadlurahmanfdev.kotlin_feature_crypto.base

import android.util.Log
import com.fadlurahmanfdev.kotlin_feature_crypto.CryptoVaultUtils
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Abstract class for asymmetric cryptography
 * */
abstract class BaseKeyPairSigningCryptoVault : BaseKeyPairCryptoVault() {
    /**
     * Generate Signature using encoded private key
     *
     * @param encodedPrivateKey encoded private key
     * @param plainText text want to be convert into signature
     * @param algorithm encryption algorithm
     * @param signatureAlgorithm algorithm want to be used for generated signature
     *
     * @return [String] encoded signature
     * */
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        algorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm,
        signatureAlgorithm: String,
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(algorithm.name).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
    }

    /**
     * Generate Signature using private key
     *
     * @param privateKey private key get from Android Keystore
     * @param plainText text want to be convert into signature
     * @param signatureAlgorithm algorithm want to be used for generated signature
     *
     * @return [String] encoded signature
     * */
    open fun generateSignature(
        privateKey: PrivateKey,
        plainText: String,
        signatureAlgorithm: String,
    ): String {
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
    }

    /**
     * Verify the signature using encoded public key.
     *
     * @param encodedPublicKey encoded public key.
     * @param signature signature want to be verified.
     * @param plainText text want to be verified.
     * @param algorithm encryption algorithm from requested key.
     * @param signatureAlgorithm algorithm of signature want to be used.
     *
     * @return [Boolean] if plain text match with the given signature.
     * */
    fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        algorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm,
        signatureAlgorithm: String,
    ): Boolean {
        return try {
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance(algorithm.name).generatePublic(publicKeySpec)
            val signer = Signature.getInstance(signatureAlgorithm)
            signer.initVerify(publicKey)
            signer.update(plainText.toByteArray())
            signer.verify(decode(signature))
            true
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed verifySignature: ${e.message}", e)
            false
        }
    }

    /**
     * Verify the signature using public key from Android Keystore.
     *
     * @param publicKey public key generated from Android KeyStore.
     * @param signature signature want to be verified.
     * @param plainText text want to be verified.
     * @param signatureAlgorithm algorithm of signature want to be used.
     *
     * @return [Boolean] if plain text match with the given signature.
     * */
    fun verifySignature(
        publicKey: PublicKey,
        signature: String,
        plainText: String,
        signatureAlgorithm: String,
    ): Boolean {
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initVerify(publicKey)
        signer.update(plainText.toByteArray())
        return signer.verify(decode(signature))
    }
}