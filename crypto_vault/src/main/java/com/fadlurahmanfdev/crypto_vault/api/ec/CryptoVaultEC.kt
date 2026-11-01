package com.fadlurahmanfdev.crypto_vault.api.ec

import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECOperation
import com.fadlurahmanfdev.crypto_vault.internal.ec.DefaultECOperation
import java.security.KeyPair

/**
 * Elliptic-curve vault for signing, hybrid ECDH encryption, and ECDH key exchange.
 *
 * Keystore-backed keys are stored in TEE / StrongBox when the device supports it.
 */
open class CryptoVaultEC internal constructor(
    private val operation: ECOperation,
) {

    companion object {
        fun create(): CryptoVaultEC {
            return CryptoVaultEC(
                operation = DefaultECOperation.create(),
            )
        }
    }

    open fun generateKey(): KeyPair = operation.generateKey()

    /** Signs [plainText] with raw private key bytes. */
    open fun generateSignature(
        privateKeyBytes: ByteArray,
        plainText: String,
        signatureAlgorithm: String = "SHA256withECDSA",
    ): ByteArray = operation.generateSignature(
        privateKeyBytes = privateKeyBytes,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm,
    )

    /** Verifies [signatureBytes] for [plainText] using raw public key bytes. */
    open fun verifySignature(
        publicKeyBytes: ByteArray,
        signatureBytes: ByteArray,
        plainText: String,
        signatureAlgorithm: String = "SHA256withECDSA",
    ): Boolean = operation.verifySignature(
        publicKeyBytes = publicKeyBytes,
        signatureBytes = signatureBytes,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm,
    )

    /**
     * Encrypts [plainText] for the holder of the private key matching [publicKeyBytes].
     *
     * Default transformation is ephemeral ECDH + SHA-256 KDF + AES-GCM.
     *
     * @throws com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException when [transformation] is not supported.
     */
    open fun encrypt(
        publicKeyBytes: ByteArray,
        transformation: String = "ECDH_AES_GCM",
        plainText: String,
    ): ByteArray = operation.encrypt(
        publicKeyBytes = publicKeyBytes,
        transformation = transformation,
        plainText = plainText,
    )

    /**
     * Decrypts [encryptedBytes] produced by [encrypt] for the same [transformation].
     *
     * @throws com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException when [transformation] is not supported.
     */
    open fun decrypt(
        privateKeyBytes: ByteArray,
        transformation: String = "ECDH_AES_GCM",
        encryptedBytes: ByteArray,
    ): String = operation.decrypt(
        privateKeyBytes = privateKeyBytes,
        transformation = transformation,
        encryptedBytes = encryptedBytes,
    )

    /** Derives a shared secret via ECDH from local private and remote public key bytes. */
    open fun generateSharedSecret(
        ourPrivateKeyBytes: ByteArray,
        otherPublicKeyBytes: ByteArray,
    ): ByteArray = operation.generateSharedSecret(
        ourPrivateKeyBytes = ourPrivateKeyBytes,
        otherPublicKeyBytes = otherPublicKeyBytes,
    )

    /** Derives a 256-bit AES key from an ECDH shared secret using SHA-256. */
    open fun derivedSharedSecret(sharedSecretBytes: ByteArray): ByteArray =
        operation.derivedSharedSecret(sharedSecretBytes = sharedSecretBytes)
}
