package com.fadlurahmanfdev.crypto_vault.internal.aes

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.domain.contracts.CryptoVaultAESAndroidKeyStoreOperation
import com.fadlurahmanfdev.crypto_vault.domain.models.EncryptedData
import com.fadlurahmanfdev.crypto_vault.internal.AndroidKeyStoreSecretKeyManager
import com.fadlurahmanfdev.crypto_vault.internal.contracts.KeyStoreSecretKeyManager
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

internal class DefaultAndroidKeyStoreAESOperation(
    private val secretKeyManager: KeyStoreSecretKeyManager = AndroidKeyStoreSecretKeyManager(),
    private val cipherFactory: (transformation: String) -> Cipher = { transformation ->
        Cipher.getInstance(transformation)
    },
    private val keyGeneratorFactory: () -> KeyGenerator = {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidKeyStoreSecretKeyManager.KEY_PROVIDER)
    },
) : CryptoVaultAESAndroidKeyStoreOperation {

    companion object {
        fun create(): DefaultAndroidKeyStoreAESOperation = DefaultAndroidKeyStoreAESOperation()
    }

    override fun generateKey(
        keyStoreAlias: String,
        keySize: Int,
        blockMode: String,
        padding: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit,
    ): SecretKey {
        return secretKeyManager.generateKey(
            algorithm = KeyProperties.KEY_ALGORITHM_AES,
            keyStoreAlias = keyStoreAlias,
            keySize = keySize,
            blockMode = blockMode,
            padding = padding,
            strongBoxBacked = strongBoxBacked,
            keyGenParameterSpecBuilder = keyGenParameterSpecBuilder,
        )
    }

    override fun generateKey(algorithmParameterSpec: AlgorithmParameterSpec): SecretKey {
        return try {
            val keyGenerator = keyGeneratorFactory()
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

    override fun getKey(keyStoreAlias: String): SecretKey? = secretKeyManager.getKey(keyStoreAlias)

    override fun isKeyExist(keyStoreAlias: String): Boolean =
        secretKeyManager.isKeyExist(keyStoreAlias)

    override fun deleteKey(keyStoreAlias: String) = secretKeyManager.deleteKey(keyStoreAlias)

    @RequiresApi(Build.VERSION_CODES.P)
    override fun isSupportStrongBox(context: Context): Boolean =
        secretKeyManager.isSupportStrongBox(context)

    override fun encrypt(
        secretKey: SecretKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
    ): EncryptedData {
        try {
            val cipher = cipherFactory(AesTransformation.raw(blockMode, padding))
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
            val cipher = cipherFactory(AesTransformation.raw(blockMode, padding))
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

    private fun mapKeyStoreCryptoFailure(e: Throwable, fallbackMessage: String): CryptoVaultException {
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
}
