package com.fadlurahmanfdev.crypto_vault.api.aes

import android.security.keystore.KeyProperties
import com.fadlurahmanfdev.crypto_vault.domain.contracts.AESSoftwareOperation
import com.fadlurahmanfdev.crypto_vault.model.EncryptedData
import com.fadlurahmanfdev.crypto_vault.internal.aes.AesTransformation
import com.fadlurahmanfdev.crypto_vault.internal.aes.DefaultSoftwareAESOperation
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

/**
 * AES vault for software keys (key material lives in app memory).
 *
 * Default path uses AES-256-GCM with a Cipher-generated IV. Prefer this for most apps unless
 * you need Android Keystore-backed keys via [CryptoVaultAESAndroidKeyStore].
 *
 * Use [create] for the default implementation. Subclass or inject [operation] to customize behavior.
 *
 * @param operation Software AES operation implementation.
 */
open class CryptoVaultAES(
    protected val operation: AESSoftwareOperation,
) {
    companion object {
        /**
         * Creates a [CryptoVaultAES] with the default software AES implementation.
         */
        fun create(): CryptoVaultAES {
            return CryptoVaultAES(
                operation = DefaultSoftwareAESOperation.create(),
            )
        }
    }

    /**
     * Generates a software AES [SecretKey].
     *
     * @param keySize Key size in bits. Default is `256`. Supported defaults are `128` and `256`.
     * @return Generated AES secret key (exportable).
     * @throws CryptoVaultException with code `INVALID_KEY_SIZE` when [keySize] is not supported,
     *         or `UNKNOWN` when generation fails.
     */
    open fun generateKey(keySize: Int = 256): SecretKey = operation.generateKey(keySize)

    /**
     * Rebuilds a software AES [SecretKey] from raw key bytes.
     *
     * Use only for importing an already established key (for example after Base64 decode). Prefer
     * [generateKey] for new keys.
     *
     * @param key Raw AES key bytes.
     * @return AES [SecretKey] wrapping [key].
     */
    open fun parseKey(keyBytes: ByteArray): SecretKey = operation.parseKey(keyBytes)

    /**
     * Generates a [GCMParameterSpec] with a random IV.
     *
     * @param ivSizeBytes IV length in bytes. Default is `12` (NIST preferred for GCM).
     * @param tagLengthBits Authentication tag length in bits. Default is `128`.
     * @return GCM parameter spec ready for encrypt/decrypt with a custom IV.
     */
    open fun generateGCMParameterSpec(
        ivSizeBytes: Int = AesTransformation.DEFAULT_GCM_IV_SIZE_BYTES,
        tagLengthBits: Int = AesTransformation.GCM_TAG_LENGTH_BITS,
    ): GCMParameterSpec = operation.generateGCMParameterSpec(ivSizeBytes, tagLengthBits)

    /**
     * Generates an [IvParameterSpec] with a random IV (typically for CBC).
     *
     * @param ivSizeBytes IV length in bytes. Default is `16` (AES block size).
     * @return IV parameter spec.
     */
    open fun generateIvParameterSpec(
        ivSizeBytes: Int = AesTransformation.DEFAULT_CBC_IV_SIZE_BYTES,
    ): IvParameterSpec = operation.generateIvParameterSpec(ivSizeBytes)

    /**
     * Encrypts [plainText] and returns ciphertext plus the Cipher-generated IV.
     *
     * @param secretKey Software AES key from [generateKey] or [parseKey].
     * @param plainText Data to encrypt.
     * @param blockMode JCA block-mode segment for `AES/blockMode/padding`. Prefer `"GCM"`.
     *        Any other Android/JCA mode string is allowed (for example `"CTR"`); unsupported
     *        combinations fail with [CryptoVaultException].
     * @param padding JCA padding segment. Prefer `"NoPadding"` with GCM.
     *        Match what you use for decrypt.
     * @return [EncryptedData] with ciphertext and IV. Store both for decrypt.
     * @throws CryptoVaultException with code `UNKNOWN` when encryption fails.
     */
    open fun encrypt(
        secretKey: SecretKey,
        plainText: String,
        blockMode: String = AesTransformation.DEFAULT_BLOCK_MODE,
        padding: String = AesTransformation.DEFAULT_PADDING,
    ): EncryptedData = operation.encrypt(
        secretKey = secretKey,
        plainText = plainText,
        blockMode = blockMode,
        padding = padding,
    )

    /**
     * Encrypts [plainTextBytes] with a caller-supplied [algorithmParameterSpec] (custom IV / GCM tag).
     *
     * @param secretKey Software AES key from [generateKey] or [parseKey].
     * @param plainTextBytes Data to encrypt.
     * @param blockMode JCA block-mode segment for `AES/blockMode/padding`. Prefer `"GCM"`.
     *        Any other Android/JCA mode string is allowed; unsupported combinations fail with
     *        [CryptoVaultException].
     * @param padding JCA padding segment. Prefer `"NoPadding"` with GCM.
     * @param algorithmParameterSpec Spec such as [GCMParameterSpec] or [IvParameterSpec].
     * @return Ciphertext only. Caller must keep the IV from [algorithmParameterSpec] for decrypt.
     * @throws CryptoVaultException with code `UNKNOWN` when encryption fails.
     */
    open fun encrypt(
        secretKey: SecretKey,
        plainTextBytes: ByteArray,
        blockMode: String = AesTransformation.DEFAULT_BLOCK_MODE,
        padding: String = AesTransformation.DEFAULT_PADDING,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray = operation.encrypt(
        secretKey = secretKey,
        plainTextBytes = plainTextBytes,
        blockMode = blockMode,
        padding = padding,
        algorithmParameterSpec = algorithmParameterSpec,
    )

    /**
     * Decrypts data produced by [encrypt] when the IV is known as raw bytes.
     *
     * For `"GCM"`, builds [GCMParameterSpec] with a 128-bit tag. For `"CBC"`, builds
     * [IvParameterSpec]. Other block modes need the [AlgorithmParameterSpec] overload.
     *
     * @param secretKey Same software AES key used for encryption.
     * @param encryptedBytes Ciphertext (for GCM includes the authentication tag).
     * @param ivBytes IV from encryption (for example [EncryptedData.ivBytes]).
     * @param blockMode JCA block-mode segment used for encryption. Prefer `"GCM"`.
     * @param padding JCA padding segment used for encryption. Prefer `"NoPadding"` with GCM.
     * @return Decrypted plaintext bytes.
     * @throws CryptoVaultException with code `INTEGRITY_CHECK_FAILED` when GCM authentication
     *         fails, `INVALID_BLOCK_MODE` when [blockMode] is not GCM/CBC for this overload,
     *         or `UNKNOWN` when decryption fails.
     */
    open fun decrypt(
        secretKey: SecretKey,
        encryptedBytes: ByteArray,
        ivBytes: ByteArray,
        blockMode: String = AesTransformation.DEFAULT_BLOCK_MODE,
        padding: String = AesTransformation.DEFAULT_PADDING,
    ): ByteArray = operation.decrypt(
        secretKey = secretKey,
        encryptedBytes = encryptedBytes,
        ivBytes = ivBytes,
        blockMode = blockMode,
        padding = padding,
    )

    /**
     * Decrypts data with a caller-supplied [algorithmParameterSpec].
     *
     * @param secretKey Same software AES key used for encryption.
     * @param encryptedBytes Ciphertext (for GCM includes the authentication tag).
     * @param blockMode JCA block-mode segment used for encryption. Prefer `"GCM"`.
     * @param padding JCA padding segment used for encryption. Prefer `"NoPadding"` with GCM.
     * @param algorithmParameterSpec Spec used (or compatible with) encryption.
     * @return Decrypted plaintext bytes.
     * @throws CryptoVaultException with code `INTEGRITY_CHECK_FAILED` when GCM authentication
     *         fails, or `UNKNOWN` when decryption fails.
     */
    open fun decrypt(
        secretKey: SecretKey,
        encryptedBytes: ByteArray,
        blockMode: String = KeyProperties.BLOCK_MODE_GCM,
        padding: String = KeyProperties.ENCRYPTION_PADDING_NONE,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray = operation.decrypt(
        secretKey = secretKey,
        encryptedBytes = encryptedBytes,
        blockMode = blockMode,
        padding = padding,
        algorithmParameterSpec = algorithmParameterSpec,
    )
}
