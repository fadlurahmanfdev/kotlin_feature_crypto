package com.fadlurahmanfdev.crypto_vault.internal

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Hybrid EC encryption using ephemeral ECDH key agreement and AES-GCM.
 *
 * Payload layout: [4-byte ephemeral public key length][ephemeral public key][12-byte IV][ciphertext]
 */
internal object EcEcdhAesGcmCipher {
    private const val GCM_IV_SIZE_BYTES = 12
    private const val GCM_TAG_SIZE_BITS = 128
    private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES = 4

    fun encrypt(
        recipientPublicKey: PublicKey,
        plainText: ByteArray,
    ): ByteArray {
        val ephemeralKeyPair = KeyPairGenerator.getInstance("EC").generateKeyPair()
        val aesKey = deriveAesKey(
            deriveSharedSecret(
                privateKey = ephemeralKeyPair.private,
                publicKey = recipientPublicKey,
            )
        )

        val iv = ByteArray(GCM_IV_SIZE_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_SIZE_BITS, iv))
        val cipherText = cipher.doFinal(plainText)

        val ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded
        return pack(ephemeralPublicKeyBytes, iv, cipherText)
    }

    fun decrypt(
        recipientPrivateKey: PrivateKey,
        encryptedPayload: ByteArray,
    ): ByteArray {
        val (ephemeralPublicKeyBytes, iv, cipherText) = unpack(encryptedPayload)
        val ephemeralPublicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(ephemeralPublicKeyBytes))
        val aesKey = deriveAesKey(
            deriveSharedSecret(
                privateKey = recipientPrivateKey,
                publicKey = ephemeralPublicKey,
            )
        )

        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_SIZE_BITS, iv))
        return cipher.doFinal(cipherText)
    }

    private fun deriveSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
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
        require(encryptedPayload.size > EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES + GCM_IV_SIZE_BYTES) {
            "Encrypted payload is too short to contain a valid ECDH-AES-GCM envelope"
        }

        val ephemeralPublicKeyLength = ByteBuffer.wrap(encryptedPayload, 0, EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES).int
        val ephemeralPublicKeyEnd = EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES + ephemeralPublicKeyLength
        val ivEnd = ephemeralPublicKeyEnd + GCM_IV_SIZE_BYTES
        require(encryptedPayload.size > ivEnd) {
            "Encrypted payload is too short to contain a valid ECDH-AES-GCM envelope"
        }

        val ephemeralPublicKeyBytes = encryptedPayload.copyOfRange(
            EPHEMERAL_PUBLIC_KEY_LENGTH_BYTES,
            ephemeralPublicKeyEnd,
        )
        val iv = encryptedPayload.copyOfRange(ephemeralPublicKeyEnd, ivEnd)
        val cipherText = encryptedPayload.copyOfRange(ivEnd, encryptedPayload.size)
        return Triple(ephemeralPublicKeyBytes, iv, cipherText)
    }
}
