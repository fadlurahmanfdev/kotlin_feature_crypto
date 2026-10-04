package com.fadlurahmanfdev.crypto_vault.domain.contracts

import android.security.keystore.KeyGenParameterSpec
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESTransformation
import com.fadlurahmanfdev.crypto_vault.domain.models.EncryptedData
import javax.crypto.SecretKey

/**
 * Contract for AES operations using keys generated and stored inside Android Keystore.
 */
interface AndroidKeyStoreAESOperation {
    /**
     * Encrypts [plainText] with an Android Keystore AES key.
     *
     * The cipher generates a fresh random IV for every call; it is returned in [EncryptedData.iv]
     * and must be stored alongside [EncryptedData.text] for decryption.
     *
     * @param secretKey Android Keystore AES key authorized for [transformation].
     * @param transformation AES transformation the key was generated for.
     * @param plainText Data to encrypt.
     * @throws CryptoVaultException with code `KEY_PERMANENTLY_INVALIDATED`,
     *         `USER_NOT_AUTHENTICATED`, or `UNKNOWN`.
     */
    fun encrypt(
        transformation: String,
        secretKey: SecretKey,
        plainText: ByteArray,
    ): EncryptedData

    /**
     * Decrypts data produced by [encrypt] with the same Android Keystore AES key.
     *
     * @param secretKey Android Keystore AES key used for encryption.
     * @param transformation AES transformation used for encryption.
     * @param encrypted Ciphertext from [EncryptedData.text].
     * @param iv IV from [EncryptedData.iv].
     * @return Decrypted data.
     * @throws CryptoVaultException with code `INTEGRITY_CHECK_FAILED`, `KEY_PERMANENTLY_INVALIDATED`,
     *         `USER_NOT_AUTHENTICATED`, or `UNKNOWN`.
     */
    fun decrypt(
        transformation: String,
        secretKey: SecretKey,
        encrypted: ByteArray,
        iv: ByteArray,
    ): ByteArray
}
