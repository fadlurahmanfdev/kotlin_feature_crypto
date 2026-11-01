package com.fadlurahmanfdev.crypto_vault.domain.contracts

import java.security.KeyPair

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

    /**
     * Encrypts [plainText] for the holder of the private key matching [publicKeyBytes].
     *
     * Default transformation is ephemeral ECDH + SHA-256 KDF + AES-GCM.
     *
     * @throws com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException when [transformation] is not supported.
     */
    fun encrypt(
        publicKeyBytes: ByteArray,
        transformation: String = "ECDH_AES_GCM",
        plainText: String,
    ): ByteArray

    /**
     * Decrypts [encryptedBytes] produced by [encrypt] for the same [transformation].
     *
     * @throws com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException when [transformation] is not supported.
     */
    fun decrypt(
        privateKeyBytes: ByteArray,
        transformation: String = "ECDH_AES_GCM",
        encryptedBytes: ByteArray,
    ): String

    /** Derives a shared secret via ECDH from local private and remote public key bytes. */
    fun generateSharedSecret(
        ourPrivateKeyBytes: ByteArray,
        otherPublicKeyBytes: ByteArray,
    ): ByteArray

    /** Derives a 256-bit AES key from an ECDH shared secret using SHA-256. */
    fun derivedSharedSecret(sharedSecretBytes: ByteArray): ByteArray
}
