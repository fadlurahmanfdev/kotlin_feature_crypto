package com.fadlurahmanfdev.crypto_vault.internal.ec

import android.security.keystore.KeyProperties
import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECOperation
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Default software EC operation for signing, hybrid ECDH+AES-GCM encryption, and ECDH key exchange.
 *
 * Hybrid encrypt payload layout:
 * `[4-byte ephemeral public key length][ephemeral public key][12-byte IV][ciphertext]`
 */
internal class DefaultECOperation : ECOperation {
    companion object {
        const val ALGORITHM = KeyProperties.KEY_ALGORITHM_EC
        const val KEY_AGREEMENT_ALGORITHM = "ECDH"

        fun create(): ECOperation = DefaultECOperation()
    }

    override fun generateKey(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM)
        return keyPairGenerator.generateKeyPair()
    }

    override fun generateSignature(
        privateKeyBytes: ByteArray,
        plainText: String,
        signatureAlgorithm: String,
    ): ByteArray {
        val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return signer.sign()
    }

    override fun verifySignature(
        publicKeyBytes: ByteArray,
        signatureBytes: ByteArray,
        plainText: String,
        signatureAlgorithm: String,
    ): Boolean {
        val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
        val publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(publicKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initVerify(publicKey)
        signer.update(plainText.toByteArray())
        return signer.verify(signatureBytes)
    }

    override fun generateSharedSecret(
        ephemeralPrivateKeyBytes: ByteArray,
        recipientPublicKeyBytes: ByteArray,
    ): ByteArray {
        val ephemeralPrivateKeySpec = PKCS8EncodedKeySpec(ephemeralPrivateKeyBytes)
        val ephemeralPrivateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(ephemeralPrivateKeySpec)

        val recipientPublicKeySpec = X509EncodedKeySpec(recipientPublicKeyBytes)
        val recipientPublicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(recipientPublicKeySpec)

        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
        keyAgreement.init(ephemeralPrivateKey)
        keyAgreement.doPhase(recipientPublicKey, true)
        return keyAgreement.generateSecret()
    }

    override fun deriveAESKey(sharedSecretBytes: ByteArray): SecretKey {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val keyBytes = sha256.digest(sharedSecretBytes)
        return SecretKeySpec(keyBytes, KeyProperties.KEY_ALGORITHM_AES)
    }
}
