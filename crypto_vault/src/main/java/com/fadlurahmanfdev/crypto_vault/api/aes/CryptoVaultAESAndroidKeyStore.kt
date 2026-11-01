package com.fadlurahmanfdev.crypto_vault.api.aes

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.domain.contracts.AESAndroidKeyStoreOperation
import com.fadlurahmanfdev.crypto_vault.model.EncryptedData
import com.fadlurahmanfdev.crypto_vault.internal.aes.AesTransformation
import com.fadlurahmanfdev.crypto_vault.internal.aes.DefaultAndroidKeyStoreAESOperation
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey

/**
 * AES vault for keys generated and stored inside Android Keystore (TEE, or StrongBox on API 28+).
 *
 * The key material never leaves the Keystore. Default path uses AES-256-GCM with randomized
 * encryption (Cipher-generated IV). Use [create] for the default implementation.
 *
 * Advanced Keystore options (user authentication, biometric invalidation, and similar) go through
 * [keyGenParameterSpecBuilder] on [generateKey], or the full [AlgorithmParameterSpec] overload.
 *
 * @param operation AES Android Keystore operation implementation.
 */
open class CryptoVaultAESAndroidKeyStore(
    protected val operation: AESAndroidKeyStoreOperation,
) {
    companion object {
        /**
         * Creates a [CryptoVaultAESAndroidKeyStore] with the default Keystore implementation.
         */
        fun create(): CryptoVaultAESAndroidKeyStore {
            return CryptoVaultAESAndroidKeyStore(
                operation = DefaultAndroidKeyStoreAESOperation.create(),
            )
        }
    }

    /**
     * Generates an AES key inside Android Keystore.
     *
     * Defaults: purpose encrypt/decrypt, [keySize] `256`, [blockMode] `"GCM"`, [padding]
     * `"NoPadding"`, randomized encryption required.
     *
     * @param keyStoreAlias Unique alias for the key entry. Must not be blank.
     * @param keySize Key size in bits. Default is `256`. Supported values are `128` and `256`.
     * @param blockMode JCA block-mode segment for `AES/blockMode/padding`. Prefer `"GCM"`.
     *        Any other Android/JCA mode string is allowed; unsupported combinations fail with
     *        [CryptoVaultException]. Must match encrypt/decrypt.
     * @param padding JCA padding segment. Prefer `"NoPadding"` with GCM.
     *        Must match encrypt/decrypt.
     * @param strongBoxBacked When `true` on API 28+, requests StrongBox. Throws
     *        `STRONG_BOX_NOT_SUPPORTED` when StrongBox is unavailable.
     * @param keyGenParameterSpecBuilder Extra [KeyGenParameterSpec.Builder] options after library
     *        defaults (for example `setUserAuthenticationRequired(true)`).
     * @return Non-exportable Android Keystore [SecretKey].
     * @throws CryptoVaultException with code `INVALID_KEY_ALIAS`, `INVALID_KEY_SIZE`,
     *         `STRONG_BOX_NOT_SUPPORTED`, or `UNKNOWN`.
     */
    open fun generateKey(
        keyStoreAlias: String,
        keySize: Int = 256,
        blockMode: String = AesTransformation.DEFAULT_BLOCK_MODE,
        padding: String = AesTransformation.DEFAULT_PADDING,
        strongBoxBacked: Boolean = false,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit = {},
    ): SecretKey = operation.generateKey(
        keyStoreAlias = keyStoreAlias,
        keySize = keySize,
        blockMode = blockMode,
        padding = padding,
        strongBoxBacked = strongBoxBacked,
        keyGenParameterSpecBuilder = keyGenParameterSpecBuilder,
    )

    /**
     * Generates an Android Keystore AES key from a fully built [algorithmParameterSpec].
     *
     * Escape hatch when you need full control over [KeyGenParameterSpec] (or compatible spec).
     *
     * @param algorithmParameterSpec Usually a [KeyGenParameterSpec].
     * @return Non-exportable Android Keystore [SecretKey].
     * @throws CryptoVaultException with code `UNKNOWN`.
     */
    open fun generateKey(algorithmParameterSpec: AlgorithmParameterSpec): SecretKey =
        operation.generateKey(algorithmParameterSpec)

    /**
     * Loads an AES [SecretKey] from Android Keystore by alias.
     *
     * @param keyStoreAlias Alias used when the key was generated.
     * @return The key, or `null` if the alias does not exist.
     */
    open fun getKey(keyStoreAlias: String): SecretKey? = operation.getKey(keyStoreAlias)

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
     * Encrypts [plainText] with an Android Keystore AES key.
     *
     * The Cipher generates a fresh IV (randomized encryption). Caller IV is not accepted.
     *
     * @param secretKey Android Keystore AES key from [generateKey] or [getKey].
     * @param plainText Data to encrypt.
     * @param blockMode JCA block-mode segment for `AES/blockMode/padding`. Prefer `"GCM"`.
     *        Must match the modes configured when the key was generated.
     * @param padding JCA padding segment. Prefer `"NoPadding"` with GCM.
     *        Must match the padding configured when the key was generated.
     * @return [EncryptedData] with ciphertext and IV. Store both for decrypt.
     * @throws CryptoVaultException with code `KEY_PERMANENTLY_INVALIDATED`,
     *         `USER_NOT_AUTHENTICATED`, or `UNKNOWN`.
     */
    open fun encrypt(
        secretKey: SecretKey,
        plainText: ByteArray,
        blockMode: String = AesTransformation.DEFAULT_BLOCK_MODE,
        padding: String = AesTransformation.DEFAULT_PADDING,
    ): EncryptedData = operation.encrypt(
        secretKey = secretKey,
        plainText = plainText,
        blockMode = blockMode,
        padding = padding,
    )

    /**
     * Decrypts data produced by [encrypt] with the same Android Keystore AES key.
     *
     * For GCM, the authentication tag is verified before any data is returned.
     *
     * @param secretKey Android Keystore AES key used for encryption.
     * @param encrypted Ciphertext from [EncryptedData.text].
     * @param iv IV from [EncryptedData.iv].
     * @param blockMode JCA block-mode segment used for encryption. Prefer `"GCM"`.
     * @param padding JCA padding segment used for encryption. Prefer `"NoPadding"` with GCM.
     * @return Decrypted data.
     * @throws CryptoVaultException with code `INTEGRITY_CHECK_FAILED` when the ciphertext or IV
     *         was modified or belongs to a different key, `INVALID_BLOCK_MODE` when [blockMode]
     *         is not GCM/CBC for this API, `KEY_PERMANENTLY_INVALIDATED` when the key was
     *         invalidated, `USER_NOT_AUTHENTICATED` when the key requires user authentication
     *         that has not happened yet, or `UNKNOWN` when decryption fails.
     */
    open fun decrypt(
        secretKey: SecretKey,
        encrypted: ByteArray,
        iv: ByteArray,
        blockMode: String = AesTransformation.DEFAULT_BLOCK_MODE,
        padding: String = AesTransformation.DEFAULT_PADDING,
    ): ByteArray = operation.decrypt(
        secretKey = secretKey,
        encrypted = encrypted,
        iv = iv,
        blockMode = blockMode,
        padding = padding,
    )
}
