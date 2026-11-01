package com.fadlurahmanfdev.crypto_vault.domain.contracts

import java.security.KeyPair
import javax.crypto.SecretKey

/**
 * Elliptic-curve vault for signing, hybrid ECDH encryption, and ECDH key exchange.
 *
 * Keystore-backed keys are stored in TEE / StrongBox when the device supports it.
 */
interface ECOperation {

    /** Generates a software EC key pair. */
    fun generateKey(): KeyPair

    /** Signs [plainText] with raw private key bytes. */
    fun generateSignature(
        privateKeyBytes: ByteArray,
        plainText: String,
        signatureAlgorithm: String = "SHA256withECDSA",
    ): ByteArray

    /** Verifies [signatureBytes] for [plainText] using raw public key bytes. */
    fun verifySignature(
        publicKeyBytes: ByteArray,
        signatureBytes: ByteArray,
        plainText: String,
        signatureAlgorithm: String = "SHA256withECDSA",
    ): Boolean

    /** Derives a shared secret via ECDH from local private and remote public key bytes. */
    fun generateSharedSecret(
        ephemeralPrivateKeyBytes: ByteArray,
        recipientPublicKeyBytes: ByteArray,
    ): ByteArray

    /** Derives a 256-bit AES key from an ECDH shared secret using SHA-256. */
    fun deriveAESKey(sharedSecretBytes: ByteArray): SecretKey
}
