package com.fadlurahmanfdev.crypto_vault.internal.base

import android.util.Log
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

abstract class BaseKeyPairSigningCryptoVault : BaseKeyPairCryptoVault() {
    open fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        algorithm: CryptoVaultAlgorithm,
        signatureAlgorithm: String,
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(algorithm.name).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
    }

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

    open fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        algorithm: CryptoVaultAlgorithm,
        signatureAlgorithm: String,
    ): Boolean {
        return try {
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance(algorithm.name).generatePublic(publicKeySpec)
            val signer = Signature.getInstance(signatureAlgorithm)
            signer.initVerify(publicKey)
            signer.update(plainText.toByteArray())
            signer.verify(decode(signature))
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed verifySignature: ${e.message}", e)
            false
        }
    }

    open fun verifySignature(
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
