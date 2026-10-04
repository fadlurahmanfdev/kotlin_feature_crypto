package com.fadlurahmanfdev.crypto_vault.api.aes

import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAESAndroidKeyStore.Companion.create
import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESTransformation
import com.fadlurahmanfdev.crypto_vault.api.enums.aes.rawTransformation
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.domain.contracts.AndroidKeyStoreAESOperation
import com.fadlurahmanfdev.crypto_vault.domain.models.EncryptedData
import com.fadlurahmanfdev.crypto_vault.internal.aes.DefaultAndroidKeyStoreAESOperation
import javax.crypto.SecretKey

/**
 * AES vault for keys generated and stored inside Android Keystore (TEE, or StrongBox on API 28+).
 *
 * The key material never leaves the Keystore. Use [create] to obtain an instance with the
 * default implementation.
 *
 * @param operation AES Android Keystore operation implementation.
 */
class CryptoVaultAESAndroidKeyStore(
    private val operation: AndroidKeyStoreAESOperation,
) {
    companion object {
        fun create(): CryptoVaultAESAndroidKeyStore {
            return CryptoVaultAESAndroidKeyStore(
                operation = DefaultAndroidKeyStoreAESOperation.create(),
            )
        }
    }

    fun encrypt(
        transformation: CryptoVaultAESTransformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
        secretKey: SecretKey,
        plainText: ByteArray,
    ): EncryptedData = operation.encrypt(
        transformation = transformation.rawTransformation(),
        secretKey = secretKey,
        plainText = plainText,
    )

    /**
     * Decrypts data produced by [encrypt] with the same Android Keystore AES key.
     *
     * For GCM, the authentication tag is verified before any data is returned, so modified
     * ciphertext or IV is rejected instead of producing corrupted output.
     *
     * @param secretKey Android Keystore AES key used for encryption.
     * @param transformation AES transformation used for encryption.
     *        Defaults to [CryptoVaultAESTransformation.GCM_NO_PADDING], matching [encrypt].
     * @param encrypted Ciphertext from [EncryptedData.text].
     * @param iv IV from [EncryptedData.iv].
     * @return Decrypted data.
     * @throws CryptoVaultException with code `INTEGRITY_CHECK_FAILED` when the ciphertext or IV
     *         was modified or belongs to a different key, `KEY_PERMANENTLY_INVALIDATED` when the
     *         key was invalidated, `USER_NOT_AUTHENTICATED` when the key requires user
     *         authentication that has not happened yet, or `UNKNOWN` when decryption fails.
     */
    fun decrypt(
        secretKey: SecretKey,
        transformation: CryptoVaultAESTransformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
        encrypted: ByteArray,
        iv: ByteArray,
    ): ByteArray = operation.decrypt(
        transformation = transformation.rawTransformation(),
        secretKey = secretKey,
        encrypted = encrypted,
        iv = iv,
    )
}
