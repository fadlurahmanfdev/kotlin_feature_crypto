package com.fadlurahmanfdev.crypto_vault.api.ec

import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECOperation
import com.fadlurahmanfdev.crypto_vault.internal.ec.DefaultECOperation
import com.fadlurahmanfdev.crypto_vault.internal.ec.EcTransformation
import java.security.KeyPair
import javax.crypto.SecretKey

/**
 * Elliptic-curve vault for ECDSA signing, ECIES hybrid encryption, and ECDH key exchange.
 *
 * Software keys default to NIST P-256. AES-GCM inside ECIES is delegated to
 * [com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES].
 *
 * Keystore-backed keys are available via [CryptoVaultECAndroidKeyStore].
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

    /** Generates a software EC P-256 key pair. */
    open fun generateKey(): KeyPair = operation.generateKey()

    /** Signs [plainTextBytes] with raw private key bytes (default `SHA256withECDSA`). */
    open fun generateSignature(
        privateKeyBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String = EcTransformation.SIGNATURE_ALGORITHM,
    ): ByteArray = operation.generateSignature(
        privateKeyBytes = privateKeyBytes,
        plainTextBytes = plainTextBytes,
        signatureAlgorithm = signatureAlgorithm,
    )

    /** Verifies [signatureBytes] for [plainTextBytes] using raw public key bytes. */
    open fun verifySignature(
        publicKeyBytes: ByteArray,
        signatureBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String = EcTransformation.SIGNATURE_ALGORITHM,
    ): Boolean = operation.verifySignature(
        publicKeyBytes = publicKeyBytes,
        signatureBytes = signatureBytes,
        plainTextBytes = plainTextBytes,
        signatureAlgorithm = signatureAlgorithm,
    )

    /**
     * ECIES-style encrypt for [recipientPublicKeyBytes].
     *
     * Generates an ephemeral P-256 key, runs ECDH, derives an AES key with HKDF-SHA256,
     * encrypts with AES-GCM via CryptoVaultAES, and returns the envelope:
     * `[4-byte eph pub length][eph pub][12-byte IV][ciphertext+tag]`.
     */
    open fun encrypt(
        recipientPublicKeyBytes: ByteArray,
        plainTextBytes: ByteArray,
    ): ByteArray = operation.encrypt(
        recipientPublicKeyBytes = recipientPublicKeyBytes,
        plainTextBytes = plainTextBytes,
    )

    /**
     * Decrypts an ECIES envelope produced by [encrypt] using the recipient private key bytes.
     */
    open fun decrypt(
        recipientPrivateKeyBytes: ByteArray,
        encryptedBytes: ByteArray,
    ): ByteArray = operation.decrypt(
        recipientPrivateKeyBytes = recipientPrivateKeyBytes,
        encryptedBytes = encryptedBytes,
    )

    /** Derives a shared secret via ECDH from local private and remote public key bytes. */
    open fun generateSharedSecret(
        ephemeralPrivateKeyBytes: ByteArray,
        recipientPublicKeyBytes: ByteArray,
    ): ByteArray = operation.generateSharedSecret(
        ephemeralPrivateKeyBytes = ephemeralPrivateKeyBytes,
        recipientPublicKeyBytes = recipientPublicKeyBytes,
    )

    /**
     * Derives a 256-bit AES key from an ECDH shared secret using HKDF-SHA256.
     *
     * @param saltBytes Optional salt (empty by default).
     * @param infoBytes Application/context info for domain separation.
     */
    open fun deriveAESKey(
        sharedSecretBytes: ByteArray,
        saltBytes: ByteArray = ByteArray(0),
        infoBytes: ByteArray = EcTransformation.defaultHkdfInfoBytes(),
    ): SecretKey = operation.deriveAESKey(
        sharedSecretBytes = sharedSecretBytes,
        saltBytes = saltBytes,
        infoBytes = infoBytes,
    )
}
