package com.fadlurahmanfdev.crypto_vault.internal.aes

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.domain.contracts.AESAndroidKeyStoreOperation
import com.fadlurahmanfdev.crypto_vault.model.EncryptedData
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

internal class DefaultAndroidKeyStoreAESOperation() : AESAndroidKeyStoreOperation {

    companion object {
        const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        const val KEY_PROVIDER = "AndroidKeyStore"

        val SUPPORTED_KEY_SIZES = setOf(128, 256)

        fun create(): DefaultAndroidKeyStoreAESOperation = DefaultAndroidKeyStoreAESOperation()
    }

    private fun keyStoreInstance() = KeyStore.getInstance(KEY_PROVIDER)
    private fun keyGenerator() = KeyGenerator.getInstance(ALGORITHM, KEY_PROVIDER)
    private fun cipher(transformation: String) = Cipher.getInstance(transformation)

    override fun generateKey(
        keyStoreAlias: String,
        keySize: Int,
        blockMode: String,
        padding: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit,
    ): SecretKey {
        try {
            requireValidKeystoreAlias(keyStoreAlias)
            requireValidKeySize(keySize)

            val purposes = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT

            val keyGenParameterSpec = KeyGenParameterSpec
                .Builder(keyStoreAlias, purposes)
                .setKeySize(keySize)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(padding)
                .setRandomizedEncryptionRequired(true)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(strongBoxBacked)
                    }
                }
                .apply(keyGenParameterSpecBuilder)
                .build()

            val keyGenerator = KeyGenerator.getInstance(ALGORITHM, KEY_PROVIDER)
            keyGenerator.init(keyGenParameterSpec)
            return keyGenerator.generateKey()
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException) {
                throw CryptoVaultExceptionCodes.strongBoxNotSupported(
                    message = "StrongBox is not available on this device",
                    cause = e,
                )
            }

            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to generate AES key in Android Keystore: ${e.message}",
                cause = e,
            )
        }
    }

    override fun generateKey(algorithmParameterSpec: AlgorithmParameterSpec): SecretKey {
        return try {
            val keyGenerator = keyGenerator()
            keyGenerator.init(algorithmParameterSpec)
            keyGenerator.generateKey()
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to generate AES key in Android Keystore: ${e.message}",
                cause = e,
            )
        }
    }

    override fun getKey(keyStoreAlias: String): SecretKey? {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getKey(keyStoreAlias, null) as SecretKey?
    }

    override fun isKeyExist(keyStoreAlias: String): Boolean {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.containsAlias(keyStoreAlias)
    }

    override fun deleteKey(keyStoreAlias: String) {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        keyStore.deleteEntry(keyStoreAlias)
    }

    @RequiresApi(Build.VERSION_CODES.P)
    override fun isSupportStrongBox(context: Context): Boolean {
        return context.packageManager.hasSystemFeature(
            android.content.pm.PackageManager.FEATURE_STRONGBOX_KEYSTORE,
        )
    }

    override fun encrypt(
        secretKey: SecretKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
    ): EncryptedData {
        try {
            val cipher = cipher(AesTransformation.raw(blockMode, padding))
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return EncryptedData(
                text = cipher.doFinal(plainText),
                iv = cipher.iv,
            )
        } catch (e: Throwable) {
            throw mapKeyStoreCryptoFailure(
                e = e,
                fallbackMessage = "Failed to encrypt with Android Keystore AES key: ${e.message}",
            )
        }
    }

    override fun decrypt(
        secretKey: SecretKey,
        encrypted: ByteArray,
        iv: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        try {
            val algorithmParameterSpec = when (blockMode) {
                AesTransformation.DEFAULT_BLOCK_MODE ->
                    GCMParameterSpec(AesTransformation.GCM_TAG_LENGTH_BITS, iv)

                AesTransformation.BLOCK_MODE_CBC -> IvParameterSpec(iv)
                else -> throw CryptoVaultExceptionCodes.invalidBlockMode(
                    message = "Parameter with specific block mode: $blockMode is not found",
                )
            }
            val cipher = cipher(AesTransformation.raw(blockMode, padding))
            cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec)
            return cipher.doFinal(encrypted)
        } catch (e: AEADBadTagException) {
            throw CryptoVaultExceptionCodes.integrityCheckFailed(
                message = "Ciphertext or IV was modified, or does not belong to this key",
                cause = e,
            )
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw mapKeyStoreCryptoFailure(
                e = e,
                fallbackMessage = "Failed to decrypt with Android Keystore AES key: ${e.message}",
            )
        }
    }

    private fun mapKeyStoreCryptoFailure(
        e: Throwable,
        fallbackMessage: String
    ): CryptoVaultException {
        return when (e) {
            is KeyPermanentlyInvalidatedException -> CryptoVaultExceptionCodes.keyPermanentlyInvalidated(
                message = "Android Keystore key is permanently invalidated and must be regenerated",
                cause = e,
            )

            is UserNotAuthenticatedException -> CryptoVaultExceptionCodes.userNotAuthenticated(
                message = "User must authenticate before using this Android Keystore key",
                cause = e,
            )

            else -> CryptoVaultExceptionCodes.unknown(
                message = fallbackMessage,
                cause = e,
            )
        }
    }

    private fun requireValidKeystoreAlias(keystoreAlias: String) {
        if (keystoreAlias.isBlank()) {
            throw CryptoVaultExceptionCodes.invalidKeyAlias(
                message = "Keystore alias must not be blank",
            )
        }
    }

    private fun requireValidKeySize(keySize: Int) {
        if (keySize !in SUPPORTED_KEY_SIZES) {
            throw CryptoVaultExceptionCodes.invalidKeySize(
                message = "Android Keystore AES key size must be one of $SUPPORTED_KEY_SIZES, but was $keySize",
            )
        }
    }
}
