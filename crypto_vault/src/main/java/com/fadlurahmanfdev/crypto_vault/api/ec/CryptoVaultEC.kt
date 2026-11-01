package com.fadlurahmanfdev.crypto_vault.api.ec

import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECOperation
import com.fadlurahmanfdev.crypto_vault.internal.ec.DefaultECOperation
import java.security.KeyPair
import javax.crypto.SecretKey

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

    /** Derives a shared secret via ECDH from local private and remote public key bytes. */
    open fun generateSharedSecret(
        ephemeralPrivateKeyBytes: ByteArray,
        recipientPublicKeyBytes: ByteArray,
    ): ByteArray = operation.generateSharedSecret(
        ephemeralPrivateKeyBytes = ephemeralPrivateKeyBytes,
        recipientPublicKeyBytes = recipientPublicKeyBytes,
    )

    /** Derives a 256-bit AES key from an ECDH shared secret using SHA-256. */
    open fun deriveAESKey(sharedSecretBytes: ByteArray): SecretKey =
        operation.deriveAESKey(sharedSecretBytes = sharedSecretBytes)
}
