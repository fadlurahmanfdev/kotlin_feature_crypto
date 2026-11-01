package com.fadlurahmanfdev.crypto_vault.domain.contracts

import java.security.KeyPair
import javax.crypto.SecretKey

/**
 * Elliptic-curve vault for signing, hybrid ECDH encryption, and ECDH key exchange.
 */
interface ECOperation {

    /** Generates a software EC P-256 key pair. */
    fun generateKey(): KeyPair

    /** Signs [plainTextBytes] with raw private key bytes. */
    fun generateSignature(
        privateKeyBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): ByteArray

    /** Verifies [signatureBytes] for [plainTextBytes] using raw public key bytes. */
    fun verifySignature(
        publicKeyBytes: ByteArray,
        signatureBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): Boolean

    /**
     * ECIES-style encrypt: ephemeral ECDH + HKDF + AES-GCM.
     *
     * @return Envelope bytes:
     * `[4-byte eph pub length][eph pub][12-byte IV][ciphertext+tag]`.
     */
    fun encrypt(
        recipientPublicKeyBytes: ByteArray,
        plainTextBytes: ByteArray,
    ): ByteArray

    /**
     * Decrypts a payload produced by [encrypt].
     */
    fun decrypt(
        recipientPrivateKeyBytes: ByteArray,
        encryptedBytes: ByteArray,
    ): ByteArray

    /** Derives a shared secret via ECDH from local private and remote public key bytes. */
    fun generateSharedSecret(
        ephemeralPrivateKeyBytes: ByteArray,
        recipientPublicKeyBytes: ByteArray,
    ): ByteArray

    /** Derives a 256-bit AES key from an ECDH shared secret using HKDF-SHA256. */
    fun deriveAESKey(
        sharedSecretBytes: ByteArray,
        saltBytes: ByteArray,
        infoBytes: ByteArray,
    ): SecretKey
}
