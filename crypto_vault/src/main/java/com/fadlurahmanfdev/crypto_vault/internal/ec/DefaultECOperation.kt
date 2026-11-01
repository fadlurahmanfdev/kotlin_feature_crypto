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

    override fun encrypt(
        publicKeyBytes: ByteArray,
        transformation: String,
        plainText: String,
    ): ByteArray {
        val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
        val publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(publicKeySpec)
        return encryptWithEcdhAesGcm(
            recipientPublicKey = publicKey,
            plainTextBytes = plainText.toByteArray(),
        )
    }

    override fun decrypt(
        privateKeyBytes: ByteArray,
        transformation: String,
        encryptedBytes: ByteArray,
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec)
        val decrypted = decryptWithEcdhAesGcm(
            recipientPrivateKey = privateKey,
            encryptedPayloadBytes = encryptedBytes,
        )
        return String(decrypted)
    }

    override fun generateSharedSecret(
        ourPrivateKeyBytes: ByteArray,
        otherPublicKeyBytes: ByteArray,
    ): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
        val privateKeySpec = PKCS8EncodedKeySpec(ourPrivateKeyBytes)
        val privateKey =
            KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec)
        val otherPublicKeySpec = X509EncodedKeySpec(otherPublicKeyBytes)
        val otherPublicKey =
            KeyFactory.getInstance(ALGORITHM).generatePublic(otherPublicKeySpec)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(otherPublicKey, true)
        return keyAgreement.generateSecret()
    }

    override fun derivedSharedSecret(sharedSecretBytes: ByteArray): ByteArray {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val keyBytes = sha256.digest(sharedSecretBytes)
        return SecretKeySpec(keyBytes, "AES").encoded
    }

    private fun encryptWithEcdhAesGcm(
        recipientPublicKey: PublicKey,
        plainTextBytes: ByteArray,
    ): ByteArray {
        val ephemeralKeyPair = KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair()
        val aesKey = deriveAesKey(
            sharedSecretBytes = deriveSharedSecret(
                privateKey = ephemeralKeyPair.private,
                publicKey = recipientPublicKey,
            ),
        )

        val ivBytes = ByteArray(GCM_IV_SIZE_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_SIZE_BITS, ivBytes))
        val cipherTextBytes = cipher.doFinal(plainTextBytes)

        val ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded
        return pack(ephemeralPublicKeyBytes, ivBytes, cipherTextBytes)
    }

    private fun decryptWithEcdhAesGcm(
        recipientPrivateKey: PrivateKey,
        encryptedPayloadBytes: ByteArray,
    ): ByteArray {
        val (ephemeralPublicKeyBytes, ivBytes, cipherTextBytes) = unpack(encryptedPayloadBytes)
        val ephemeralPublicKey = KeyFactory.getInstance(ALGORITHM)
            .generatePublic(X509EncodedKeySpec(ephemeralPublicKeyBytes))
        val aesKey = deriveAesKey(
            sharedSecretBytes = deriveSharedSecret(
                privateKey = recipientPrivateKey,
                publicKey = ephemeralPublicKey,
            ),
        )

        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_SIZE_BITS, ivBytes))
        return cipher.doFinal(cipherTextBytes)
    }

    private fun deriveSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }

    private fun deriveAesKey(sharedSecretBytes: ByteArray): SecretKeySpec {
        val keyBytes = MessageDigest.getInstance("SHA-256").digest(sharedSecretBytes)
        return SecretKeySpec(keyBytes, "AES")
    }

    private fun pack(
        ephemeralPublicKeyBytes: ByteArray,
        ivBytes: ByteArray,
        cipherTextBytes: ByteArray,
    ): ByteArray {
        val lengthPrefix = ByteBuffer.allocate(EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES)
            .putInt(ephemeralPublicKeyBytes.size)
            .array()
        return lengthPrefix + ephemeralPublicKeyBytes + ivBytes + cipherTextBytes
    }

    private fun unpack(
        encryptedPayloadBytes: ByteArray,
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val minEnvelopeSize = EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES + GCM_IV_SIZE_BYTES
        require(encryptedPayloadBytes.size > minEnvelopeSize) {
            "Encrypted payload is too short to contain a valid ECDH-AES-GCM envelope"
        }

        val ephemeralPublicKeyLength = ByteBuffer
            .wrap(encryptedPayloadBytes, 0, EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES)
            .int
        require(ephemeralPublicKeyLength >= 0) {
            "Invalid ephemeral public key length prefix"
        }

        val payloadSize = encryptedPayloadBytes.size.toLong()
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

        val ephemeralPublicKeyBytes = encryptedPayloadBytes.copyOfRange(
            EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES,
            ephemeralPublicKeyEndIndex,
        )
        val ivBytes = encryptedPayloadBytes.copyOfRange(ephemeralPublicKeyEndIndex, ivEndIndex)
        val cipherTextBytes =
            encryptedPayloadBytes.copyOfRange(ivEndIndex, encryptedPayloadBytes.size)
        return Triple(ephemeralPublicKeyBytes, ivBytes, cipherTextBytes)
    }
}
