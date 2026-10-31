package com.fadlurahmanfdev.crypto_vault.internal.ec

import com.fadlurahmanfdev.crypto_vault.core.EcEcdhAesGcmCipher
import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECOperation
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec

/**
 * Elliptic-curve vault for signing, hybrid ECDH encryption, and ECDH key exchange.
 *
 * Keystore-backed keys are stored in TEE / StrongBox when the device supports it.
 */
internal class DefaultECOperation : ECOperation {
    companion object {
        const val ALGORITHM = "EC"
        const val KEY_AGREEMENT_ALGORITHM = "ECDH"
        fun create() : ECOperation {
            return DefaultECOperation()
        }
    }

    override fun generateKey(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM)
        val key = keyPairGenerator.generateKeyPair()
        return key
    }

    override fun generateSignature(
        encodedPrivateKey: ByteArray,
        plainText: String,
        signatureAlgorithm: String
    ): ByteArray {
        val privateKeySpec = PKCS8EncodedKeySpec(encodedPrivateKey)
        val privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return signer.sign()
    }

    override fun verifySignature(
        encodedPublicKey: ByteArray,
        signature: ByteArray,
        plainText: String,
        signatureAlgorithm: String
    ): Boolean {
        val publicKeySpec = X509EncodedKeySpec(encodedPublicKey)
        val publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(publicKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initVerify(publicKey)
        signer.update(plainText.toByteArray())
        return signer.verify(signature)
    }

    override fun encrypt(
        encodedPublicKey: ByteArray,
        transformation: String,
        plainText: String
    ): ByteArray {
        val publicKeySpec = X509EncodedKeySpec(encodedPublicKey)
        val publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(publicKeySpec)
        val encrypted = EcEcdhAesGcmCipher.encrypt(
            recipientPublicKey = publicKey,
            plainText = plainText.toByteArray(),
        )
        return encrypted
    }

    override fun decrypt(
        encodedPrivateKey: ByteArray,
        transformation: String,
        encrypted: ByteArray
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(encodedPrivateKey)
        val privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec)
        val decrypted = EcEcdhAesGcmCipher.decrypt(
            recipientPrivateKey = privateKey,
            encryptedPayload = encrypted,
        )
        return String(decrypted)
    }

    override fun generateSharedSecret(
        encodedPrivateKey: ByteArray,
        encodedPublicKey: ByteArray
    ): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
        val privateKeySpec = PKCS8EncodedKeySpec(encodedPrivateKey)
        val privateKey =
            KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec)
        val otherPublicKeySpec = X509EncodedKeySpec(encodedPublicKey)
        val otherPublicKey =
            KeyFactory.getInstance(ALGORITHM).generatePublic(otherPublicKeySpec)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(otherPublicKey, true)
        return keyAgreement.generateSecret()
    }

    override fun derivedSharedSecret(sharedSecret: ByteArray): ByteArray {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val keyBytes = sha256.digest(sharedSecret)
        return SecretKeySpec(keyBytes, "AES").encoded
    }
}