package com.fadlurahmanfdev.crypto_vault.api.rsa

import com.fadlurahmanfdev.crypto_vault.domain.contracts.RSASoftwareOperation
import com.fadlurahmanfdev.crypto_vault.internal.rsa.DefaultSoftwareRSAOperation
import com.fadlurahmanfdev.crypto_vault.internal.rsa.RsaTransformation
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec

/**
 * RSA vault for software key pairs (key material lives in app memory).
 *
 * Default path uses 2048-bit keys, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` for encrypt/decrypt,
 * and `SHA256withRSA` for signatureBytess. Prefer [CryptoVaultRSAAndroidKeyStore] when the private key
 * should never leave the device.
 *
 * Use [create] for the default implementation. Subclass or inject [operation] to customize behavior.
 *
 * @param operation Software RSA operation implementation.
 */
open class CryptoVaultRSA(
    protected val operation: RSASoftwareOperation,
) {
    companion object {
        /**
         * Creates a [CryptoVaultRSA] with the default software RSA implementation.
         */
        fun create(): CryptoVaultRSA {
            return CryptoVaultRSA(
                operation = DefaultSoftwareRSAOperation.create(),
            )
        }
    }

    /**
     * Generates a software RSA [KeyPair].
     *
     * @param keySize Key size in bits. Default is `2048`. Supported defaults are `2048`, `3072`,
     *        and `4096`.
     * @return Generated RSA key pair (exportable).
     * @throws CryptoVaultException with code `INVALID_KEY_SIZE` when [keySize] is not supported,
     *         or `UNKNOWN` when generation fails.
     */
    open fun generateKey(keySize: Int = RsaTransformation.DEFAULT_KEY_SIZE): KeyPair =
        operation.generateKey(keySize)

    /**
     * Rebuilds an RSA [PublicKey] from X.509 encoded bytes.
     *
     * @param key Raw X.509 public key bytes.
     * @return Parsed public key.
     * @throws CryptoVaultException with code `UNKNOWN` when parsing fails.
     */
    open fun parsePublicKey(publicKeyBytes: ByteArray): PublicKey = operation.parsePublicKey(publicKeyBytes)

    /**
     * Rebuilds an RSA [PrivateKey] from PKCS#8 encoded bytes.
     *
     * @param key Raw PKCS#8 private key bytes.
     * @return Parsed private key.
     * @throws CryptoVaultException with code `UNKNOWN` when parsing fails.
     */
    open fun parsePrivateKey(privateKeyBytes: ByteArray): PrivateKey = operation.parsePrivateKey(privateKeyBytes)

    /**
     * Encrypts [plainTextBytes] with [publicKey].
     *
     * @param publicKey RSA public key from [generateKey] or [parsePublicKey].
     * @param plainTextBytes Data to encrypt. Must fit RSA size limits for the chosen padding.
     * @param blockMode JCA block-mode segment for `RSA/blockMode/padding`. Prefer `"ECB"`.
     * @param padding JCA padding segment. Prefer `"OAEPWithSHA-256AndMGF1Padding"`.
     * @return Ciphertext bytes.
     * @throws CryptoVaultException with code `UNKNOWN` when encryption fails.
     */
    open fun encrypt(
        publicKey: PublicKey,
        plainTextBytes: ByteArray,
        blockMode: String = RsaTransformation.DEFAULT_BLOCK_MODE,
        padding: String = RsaTransformation.DEFAULT_PADDING,
    ): ByteArray = operation.encrypt(
        publicKey = publicKey,
        plainTextBytes = plainTextBytes,
        blockMode = blockMode,
        padding = padding,
    )

    /**
     * Encrypts [plainTextBytes] with a caller-supplied [algorithmParameterSpec] (for example OAEP).
     *
     * @param publicKey RSA public key from [generateKey] or [parsePublicKey].
     * @param plainTextBytes Data to encrypt.
     * @param blockMode JCA block-mode segment for `RSA/blockMode/padding`. Prefer `"ECB"`.
     * @param padding JCA padding segment. Prefer `"OAEPWithSHA-256AndMGF1Padding"`.
     * @param algorithmParameterSpec Spec such as `OAEPParameterSpec`.
     * @return Ciphertext bytes.
     * @throws CryptoVaultException with code `UNKNOWN` when encryption fails.
     */
    open fun encrypt(
        publicKey: PublicKey,
        plainTextBytes: ByteArray,
        blockMode: String = RsaTransformation.DEFAULT_BLOCK_MODE,
        padding: String = RsaTransformation.DEFAULT_PADDING,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray = operation.encrypt(
        publicKey = publicKey,
        plainTextBytes = plainTextBytes,
        blockMode = blockMode,
        padding = padding,
        algorithmParameterSpec = algorithmParameterSpec,
    )

    /**
     * Decrypts [encryptedBytes] with [privateKey].
     *
     * @param privateKey Same software RSA private key used for encryption.
     * @param encryptedBytes Ciphertext.
     * @param blockMode JCA block-mode segment used for encryption. Prefer `"ECB"`.
     * @param padding JCA padding segment used for encryption. Prefer
     *        `"OAEPWithSHA-256AndMGF1Padding"`.
     * @return Decrypted plaintext bytes.
     * @throws CryptoVaultException with code `UNKNOWN` when decryption fails.
     */
    open fun decrypt(
        privateKey: PrivateKey,
        encryptedBytes: ByteArray,
        blockMode: String = RsaTransformation.DEFAULT_BLOCK_MODE,
        padding: String = RsaTransformation.DEFAULT_PADDING,
    ): ByteArray = operation.decrypt(
        privateKey = privateKey,
        encryptedBytes = encryptedBytes,
        blockMode = blockMode,
        padding = padding,
    )

    /**
     * Decrypts [encryptedBytes] with a caller-supplied [algorithmParameterSpec].
     *
     * @param privateKey Same software RSA private key used for encryption.
     * @param encryptedBytes Ciphertext.
     * @param blockMode JCA block-mode segment used for encryption. Prefer `"ECB"`.
     * @param padding JCA padding segment used for encryption.
     * @param algorithmParameterSpec Spec used (or compatible with) encryption.
     * @return Decrypted plaintext bytes.
     * @throws CryptoVaultException with code `UNKNOWN` when decryption fails.
     */
    open fun decrypt(
        privateKey: PrivateKey,
        encryptedBytes: ByteArray,
        blockMode: String = RsaTransformation.DEFAULT_BLOCK_MODE,
        padding: String = RsaTransformation.DEFAULT_PADDING,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray = operation.decrypt(
        privateKey = privateKey,
        encryptedBytes = encryptedBytes,
        blockMode = blockMode,
        padding = padding,
        algorithmParameterSpec = algorithmParameterSpec,
    )

    /**
     * Signs [plainTextBytes] with [privateKey].
     *
     * @param privateKey RSA private key from [generateKey] or [parsePrivateKey].
     * @param plainTextBytes Data to sign.
     * @param signatureAlgorithm JCA signature algorithm. Prefer `"SHA256withRSA"`.
     * @return Signature bytes.
     * @throws CryptoVaultException with code `UNKNOWN` when signing fails.
     */
    open fun sign(
        privateKey: PrivateKey,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String = RsaTransformation.DEFAULT_SIGNATURE_ALGORITHM,
    ): ByteArray = operation.sign(
        privateKey = privateKey,
        plainTextBytes = plainTextBytes,
        signatureAlgorithm = signatureAlgorithm,
    )

    /**
     * Verifies [signatureBytes] for [plainTextBytes] with [publicKey].
     *
     * Returns `false` when the signatureBytes does not match. Unexpected setup failures throw
     * [CryptoVaultException].
     *
     * @param publicKey Matching RSA public key.
     * @param signatureBytes Signature bytes from [sign].
     * @param plainTextBytes Original data that was signed.
     * @param signatureAlgorithm JCA signature algorithm used for signing. Prefer `"SHA256withRSA"`.
     * @return `true` when the signatureBytes is valid.
     * @throws CryptoVaultException with code `UNKNOWN` when verification cannot be set up.
     */
    open fun verify(
        publicKey: PublicKey,
        signatureBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String = RsaTransformation.DEFAULT_SIGNATURE_ALGORITHM,
    ): Boolean = operation.verify(
        publicKey = publicKey,
        signatureBytes = signatureBytes,
        plainTextBytes = plainTextBytes,
        signatureAlgorithm = signatureAlgorithm,
    )
}
