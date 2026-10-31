package com.fadlurahmanfdev.crypto_vault.domain.contracts

import java.security.KeyPair

/**
 * Elliptic-curve vault for signing, hybrid ECDH encryption, and ECDH key exchange.
 *
 * Keystore-backed keys are stored in TEE / StrongBox when the device supports it.
 */
interface ECOperation {

    /** Generates a software EC key pair encoded as Base64. */
    fun generateKey(): KeyPair

    /** Signs [plainText] with a Base64-encoded private key. */
    fun generateSignature(
        encodedPrivateKey: ByteArray,
        plainText: String,
        signatureAlgorithm: String = "SHA256withECDSA",
    ): ByteArray

    /** Verifies [signature] for [plainText] using a Base64-encoded public key. */
    fun verifySignature(
        encodedPublicKey: ByteArray,
        signature: ByteArray,
        plainText: String,
        signatureAlgorithm: String = "SHA256withECDSA",
    ): Boolean

    /**
     * Encrypts [plainText] for the holder of the private key matching [encodedPublicKey].
     *
     * Uses [com.fadlurahmanfdev.crypto_vault.core.enum.ec.CryptoVaultECTransformation.ECDH_AES_GCM]: ephemeral ECDH + SHA-256 KDF + AES-GCM.
     *
     * @throws com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException when [transformation] is not supported.
     */
    fun encrypt(
        encodedPublicKey: ByteArray,
        transformation: String = "ECDH_AES_GCM",
        plainText: String,
    ): ByteArray
    /**
     * Decrypts [encryptedText] produced by [encrypt] for the same [transformation].
     *
     * @throws com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException when [transformation] is not supported.
     */
     fun decrypt(
        encodedPrivateKey: ByteArray,
        transformation: String = "ECDH_AES_GCM",
        encrypted: ByteArray,
    ): String

    /** Derives a shared secret via ECDH from local private and remote public keys. */
    fun generateSharedSecret(
        encodedPrivateKey: ByteArray,
        encodedPublicKey: ByteArray,
    ): ByteArray

    /** Derives a 256-bit AES key from an ECDH shared secret using SHA-256. */
    fun derivedSharedSecret(sharedSecret: ByteArray): ByteArray
}