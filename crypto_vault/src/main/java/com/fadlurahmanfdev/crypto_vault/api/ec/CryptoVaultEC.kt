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
    private val operation: ECOperation
) {

    companion object {
        fun create(): CryptoVaultEC {
            return CryptoVaultEC(
                operation = DefaultECOperation.create()
            )
        }
    }

    open fun generateKey(): KeyPair = operation.generateKey()

    /** Signs [plainText] with a Base64-encoded private key. */
    open fun generateSignature(
        encodedPrivateKey: ByteArray,
        plainText: String,
        signatureAlgorithm: String = "SHA256withECDSA"
    ): ByteArray = operation.generateSignature(
        encodedPrivateKey = encodedPrivateKey,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm
    )

    /** Verifies [signature] for [plainText] using a Base64-encoded public key. */
    open fun verifySignature(
        encodedPublicKey: ByteArray,
        signature: ByteArray,
        plainText: String,
        signatureAlgorithm: String = "SHA256withECDSA"
    ): Boolean = operation.verifySignature(
        encodedPublicKey = encodedPublicKey,
        signature = signature,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm
    )

    /**
     * Encrypts [plainText] for the holder of the private key matching [encodedPublicKey].
     *
     * Uses [com.fadlurahmanfdev.crypto_vault.core.enum.ec.CryptoVaultECTransformation.ECDH_AES_GCM]: ephemeral ECDH + SHA-256 KDF + AES-GCM.
     *
     * @throws com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException when [transformation] is not supported.
     */
    open fun encrypt(
        encodedPublicKey: ByteArray,
        transformation: String = "ECDH_AES_GCM",
        plainText: String,
    ): ByteArray = operation.encrypt(
        encodedPublicKey = encodedPublicKey,
        transformation = transformation,
        plainText = plainText
    )

    /**
     * Decrypts [encryptedText] produced by [encrypt] for the same [transformation].
     *
     * @throws com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException when [transformation] is not supported.
     */
    open fun decrypt(
        encodedPrivateKey: ByteArray,
        transformation: String = "ECDH_AES_GCM",
        encrypted: ByteArray,
    ): String = operation.decrypt(
        encodedPrivateKey = encodedPrivateKey,
        transformation = transformation,
        encrypted = encrypted,
    )

    /** Derives a shared secret via ECDH from local private and remote public keys. */
    open fun generateSharedSecret(
        ourEncodedPrivateKey: ByteArray,
        otherEncodedPublicKey: ByteArray,
    ): ByteArray = operation.generateSharedSecret(
        ourEncodedPrivateKey = ourEncodedPrivateKey,
        otherEncodedPublicKey = otherEncodedPublicKey,
    )

    /** Derives a 256-bit AES key from an ECDH shared secret using SHA-256. */
    open fun derivedSharedSecret(sharedSecret: ByteArray): ByteArray = operation.derivedSharedSecret(
        sharedSecret = sharedSecret
    )
}