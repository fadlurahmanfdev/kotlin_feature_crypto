package com.fadlurahmanfdev.crypto_vault.internal.ec

import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECOperation
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Default software EC operation for signing, hybrid ECDH+AES-GCM encryption, and ECDH key exchange.
 *
 * Hybrid encrypt payload layout:
 * `[4-byte ephemeral public key length][ephemeral public key][12-byte IV][ciphertext]`
 */
internal class DefaultECOperation : ECOperation {
    companion object {
        const val ALGORITHM = "EC"
        const val KEY_AGREEMENT_ALGORITHM = "ECDH"
        private const val GCM_IV_SIZE_BYTES = 12
        private const val GCM_TAG_SIZE_BITS = 128
        private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES = 4

        fun create(): ECOperation = DefaultECOperation()
    }

    override fun generateKey(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM)
        return keyPairGenerator.generateKeyPair()
    }

    override fun generateSignature(
        encodedPrivateKey: ByteArray,
        plainText: String,
        signatureAlgorithm: String,
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
        signatureAlgorithm: String,
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
        plainText: String,
    ): ByteArray {
        val publicKeySpec = X509EncodedKeySpec(encodedPublicKey)
        val publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(publicKeySpec)
        return encryptWithEcdhAesGcm(
            recipientPublicKey = publicKey,
            plainText = plainText.toByteArray(),
        )
    }

    override fun decrypt(
        encodedPrivateKey: ByteArray,
        transformation: String,
        encrypted: ByteArray,
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(encodedPrivateKey)
        val privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec)
        val decrypted = decryptWithEcdhAesGcm(
            recipientPrivateKey = privateKey,
            encryptedPayload = encrypted,
        )
        return String(decrypted)
    }

    override fun generateSharedSecret(
        ourEncodedPrivateKey: ByteArray,
        otherEncodedPublicKey: ByteArray,
    ): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
        val privateKeySpec = PKCS8EncodedKeySpec(ourEncodedPrivateKey)
        val privateKey =
            KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec)
        val otherPublicKeySpec = X509EncodedKeySpec(otherEncodedPublicKey)
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

    private fun encryptWithEcdhAesGcm(
        recipientPublicKey: PublicKey,
        plainText: ByteArray,
    ): ByteArray {
        val ephemeralKeyPair = KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair()
        val aesKey = deriveAesKey(
            deriveSharedSecret(
                privateKey = ephemeralKeyPair.private,
                publicKey = recipientPublicKey,
            ),
        )

        val iv = ByteArray(GCM_IV_SIZE_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_SIZE_BITS, iv))
        val cipherText = cipher.doFinal(plainText)

        val ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded
        return pack(ephemeralPublicKeyBytes, iv, cipherText)
    }

    private fun decryptWithEcdhAesGcm(
        recipientPrivateKey: PrivateKey,
        encryptedPayload: ByteArray,
    ): ByteArray {
        val (ephemeralPublicKeyBytes, iv, cipherText) = unpack(encryptedPayload)
        val ephemeralPublicKey = KeyFactory.getInstance(ALGORITHM)
            .generatePublic(X509EncodedKeySpec(ephemeralPublicKeyBytes))
        val aesKey = deriveAesKey(
            deriveSharedSecret(
                privateKey = recipientPrivateKey,
                publicKey = ephemeralPublicKey,
            ),
        )

        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_SIZE_BITS, iv))
        return cipher.doFinal(cipherText)
    }

    private fun deriveSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }

    private fun deriveAesKey(sharedSecret: ByteArray): SecretKeySpec {
        val keyBytes = MessageDigest.getInstance("SHA-256").digest(sharedSecret)
        return SecretKeySpec(keyBytes, "AES")
    }

    private fun pack(
        ephemeralPublicKeyBytes: ByteArray,
        iv: ByteArray,
        cipherText: ByteArray,
    ): ByteArray {
        val lengthPrefix = ByteBuffer.allocate(EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES)
            .putInt(ephemeralPublicKeyBytes.size)
            .array()
        return lengthPrefix + ephemeralPublicKeyBytes + iv + cipherText
    }

    private fun unpack(encryptedPayload: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val minEnvelopeSize = EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES + GCM_IV_SIZE_BYTES
        require(encryptedPayload.size > minEnvelopeSize) {
            "Encrypted payload is too short to contain a valid ECDH-AES-GCM envelope"
        }

        val ephemeralPublicKeyLength = ByteBuffer
            .wrap(encryptedPayload, 0, EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES)
            .int
        require(ephemeralPublicKeyLength >= 0) {
            "Invalid ephemeral public key length prefix"
        }

        val payloadSize = encryptedPayload.size.toLong()
        val ephemeralPublicKeyEnd =
            EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES.toLong() + ephemeralPublicKeyLength
        val ivEnd = ephemeralPublicKeyEnd + GCM_IV_SIZE_BYTES

        require(ephemeralPublicKeyEnd <= Int.MAX_VALUE && ivEnd <= Int.MAX_VALUE) {
            "Invalid ephemeral public key length prefix"
        }
        require(ivEnd <= payloadSize) {
            "Encrypted payload is too short to contain a valid ECDH-AES-GCM envelope"
        }
        require(ivEnd < payloadSize) {
            "Encrypted payload is too short to contain ciphertext"
        }

        val ephemeralPublicKeyEndIndex = ephemeralPublicKeyEnd.toInt()
        val ivEndIndex = ivEnd.toInt()

        val ephemeralPublicKeyBytes = encryptedPayload.copyOfRange(
            EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES,
            ephemeralPublicKeyEndIndex,
        )
        val iv = encryptedPayload.copyOfRange(ephemeralPublicKeyEndIndex, ivEndIndex)
        val cipherText = encryptedPayload.copyOfRange(ivEndIndex, encryptedPayload.size)
        return Triple(ephemeralPublicKeyBytes, iv, cipherText)
    }
}
