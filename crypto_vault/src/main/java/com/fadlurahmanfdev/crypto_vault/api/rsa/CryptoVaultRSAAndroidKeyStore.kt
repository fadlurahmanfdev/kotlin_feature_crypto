package com.fadlurahmanfdev.crypto_vault.api.rsa

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.domain.contracts.CryptoVaultRSAAndroidKeyStoreOperation
import com.fadlurahmanfdev.crypto_vault.internal.rsa.DefaultAndroidKeyStoreRSAOperation
import com.fadlurahmanfdev.crypto_vault.internal.rsa.RsaTransformation
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec

/**
 * RSA vault for key pairs generated and stored inside Android Keystore (TEE, or StrongBox on
 * API 28+).
 *
 * The private key material never leaves the Keystore. Defaults: 2048-bit key, OAEP encryption
 * padding, PSS signature padding, SHA-256/SHA-512 digests. Use [create] for the default
 * implementation.
 *
 * Advanced Keystore options go through [keyGenParameterSpecBuilder] on [generateKey], or the full
 * [AlgorithmParameterSpec] overload.
 *
 * @param operation RSA Android Keystore operation implementation.
 */
open class CryptoVaultRSAAndroidKeyStore(
    protected val operation: CryptoVaultRSAAndroidKeyStoreOperation,
) {
    companion object {
        /**
         * Creates a [CryptoVaultRSAAndroidKeyStore] with the default Keystore implementation.
         */
        fun create(): CryptoVaultRSAAndroidKeyStore {
            return CryptoVaultRSAAndroidKeyStore(
                operation = DefaultAndroidKeyStoreRSAOperation.create(),
            )
        }
    }

    /**
     * Generates an RSA key pair inside Android Keystore.
     *
     * @param keyStoreAlias Unique alias for the key entry. Must not be blank.
     * @param keySize Key size in bits. Default is `2048`. Supported values are `2048`, `3072`,
     *        and `4096`.
     * @param encryptionPaddings Keystore encryption paddings (for example `"OAEPPadding"`,
     *        `"PKCS1Padding"`).
     * @param signaturePaddings Keystore signature paddings (for example `"PSS"`, `"PKCS1"`).
     * @param digests Digest algorithms allowed for this key.
     * @param strongBoxBacked When `true` on API 28+, requests StrongBox.
     * @param keyGenParameterSpecBuilder Extra [KeyGenParameterSpec.Builder] options after library
     *        defaults.
     * @return Non-exportable Android Keystore [KeyPair].
     * @throws CryptoVaultException with code `INVALID_KEY_ALIAS`, `INVALID_KEY_SIZE`,
     *         `STRONG_BOX_NOT_SUPPORTED`, or `UNKNOWN`.
     */
    open fun generateKey(
        keyStoreAlias: String,
        keySize: Int = RsaTransformation.DEFAULT_KEY_SIZE,
        encryptionPaddings: Array<String> = arrayOf(RsaTransformation.DEFAULT_KEYSTORE_ENCRYPTION_PADDING),
        signaturePaddings: Array<String> = arrayOf(RsaTransformation.DEFAULT_KEYSTORE_SIGNATURE_PADDING),
        digests: Array<String> = RsaTransformation.DEFAULT_DIGESTS,
        strongBoxBacked: Boolean = false,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit = {},
    ): KeyPair = operation.generateKey(
        keyStoreAlias = keyStoreAlias,
        keySize = keySize,
        encryptionPaddings = encryptionPaddings,
        signaturePaddings = signaturePaddings,
        digests = digests,
        strongBoxBacked = strongBoxBacked,
        keyGenParameterSpecBuilder = keyGenParameterSpecBuilder,
    )

    /**
     * Generates an Android Keystore RSA key pair from a fully built [algorithmParameterSpec].
     *
     * @param algorithmParameterSpec Usually a [KeyGenParameterSpec].
     * @return Non-exportable Android Keystore [KeyPair].
     * @throws CryptoVaultException with code `UNKNOWN`.
     */
    open fun generateKey(algorithmParameterSpec: AlgorithmParameterSpec): KeyPair =
        operation.generateKey(algorithmParameterSpec)

    /**
     * Loads an RSA [PrivateKey] from Android Keystore by alias.
     *
     * @return The private key, or `null` if the alias does not exist.
     */
    open fun getPrivateKey(keyStoreAlias: String): PrivateKey? =
        operation.getPrivateKey(keyStoreAlias)

    /**
     * Loads an RSA [PublicKey] from Android Keystore by alias.
     *
     * @return The public key, or `null` if the alias does not exist.
     */
    open fun getPublicKey(keyStoreAlias: String): PublicKey? =
        operation.getPublicKey(keyStoreAlias)

    /**
     * Returns whether an entry exists for [keyStoreAlias] in Android Keystore.
     */
    open fun isKeyExist(keyStoreAlias: String): Boolean = operation.isKeyExist(keyStoreAlias)

    /**
     * Deletes the Keystore entry for [keyStoreAlias] if it exists.
     */
    open fun deleteKey(keyStoreAlias: String) = operation.deleteKey(keyStoreAlias)

    /**
     * Returns whether this device supports StrongBox Keystore.
     */
    @RequiresApi(Build.VERSION_CODES.P)
    open fun isSupportStrongBox(context: Context): Boolean =
        operation.isSupportStrongBox(context)

    /**
     * Encrypts [plainText] with an Android Keystore RSA public key.
     *
     * @param publicKey Keystore public key from [generateKey] or [getPublicKey].
     * @param plainText Data to encrypt.
     * @param blockMode JCA block-mode segment for `RSA/blockMode/padding`. Prefer `"ECB"`.
     * @param padding JCA cipher padding. Prefer `"OAEPWithSHA-256AndMGF1Padding"` when the key
     *        was generated with `"OAEPPadding"`.
     * @return Ciphertext bytes.
     * @throws CryptoVaultException with code `KEY_PERMANENTLY_INVALIDATED`,
     *         `USER_NOT_AUTHENTICATED`, or `UNKNOWN`.
     */
    open fun encrypt(
        publicKey: PublicKey,
        plainText: ByteArray,
        blockMode: String = RsaTransformation.DEFAULT_BLOCK_MODE,
        padding: String = RsaTransformation.DEFAULT_PADDING,
    ): ByteArray = operation.encrypt(
        publicKey = publicKey,
        plainText = plainText,
        blockMode = blockMode,
        padding = padding,
    )

    /**
     * Encrypts [plainText] with a caller-supplied [algorithmParameterSpec].
     */
    open fun encrypt(
        publicKey: PublicKey,
        plainText: ByteArray,
        blockMode: String = RsaTransformation.DEFAULT_BLOCK_MODE,
        padding: String = RsaTransformation.DEFAULT_PADDING,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray = operation.encrypt(
        publicKey = publicKey,
        plainText = plainText,
        blockMode = blockMode,
        padding = padding,
        algorithmParameterSpec = algorithmParameterSpec,
    )

    /**
     * Decrypts [encrypted] with an Android Keystore RSA private key.
     *
     * @throws CryptoVaultException with code `KEY_PERMANENTLY_INVALIDATED`,
     *         `USER_NOT_AUTHENTICATED`, or `UNKNOWN`.
     */
    open fun decrypt(
        privateKey: PrivateKey,
        encrypted: ByteArray,
        blockMode: String = RsaTransformation.DEFAULT_BLOCK_MODE,
        padding: String = RsaTransformation.DEFAULT_PADDING,
    ): ByteArray = operation.decrypt(
        privateKey = privateKey,
        encrypted = encrypted,
        blockMode = blockMode,
        padding = padding,
    )

    /**
     * Decrypts [encrypted] with a caller-supplied [algorithmParameterSpec].
     */
    open fun decrypt(
        privateKey: PrivateKey,
        encrypted: ByteArray,
        blockMode: String = RsaTransformation.DEFAULT_BLOCK_MODE,
        padding: String = RsaTransformation.DEFAULT_PADDING,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray = operation.decrypt(
        privateKey = privateKey,
        encrypted = encrypted,
        blockMode = blockMode,
        padding = padding,
        algorithmParameterSpec = algorithmParameterSpec,
    )

    /**
     * Signs [plainText] with an Android Keystore RSA private key.
     *
     * Prefer `"SHA256withRSA"` or `"SHA256withRSA/PSS"` depending on the signature padding used
     * when the key was generated.
     *
     * @throws CryptoVaultException with code `KEY_PERMANENTLY_INVALIDATED`,
     *         `USER_NOT_AUTHENTICATED`, or `UNKNOWN`.
     */
    open fun sign(
        privateKey: PrivateKey,
        plainText: ByteArray,
        signatureAlgorithm: String = RsaTransformation.DEFAULT_KEYSTORE_SIGNATURE_ALGORITHM,
    ): ByteArray = operation.sign(
        privateKey = privateKey,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm,
    )

    /**
     * Verifies [signature] for [plainText] with an Android Keystore RSA public key.
     *
     * Returns `false` when the signature does not match. Unexpected setup failures throw
     * [CryptoVaultException].
     */
    open fun verify(
        publicKey: PublicKey,
        signature: ByteArray,
        plainText: ByteArray,
        signatureAlgorithm: String = RsaTransformation.DEFAULT_KEYSTORE_SIGNATURE_ALGORITHM,
    ): Boolean = operation.verify(
        publicKey = publicKey,
        signature = signature,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm,
    )
}
