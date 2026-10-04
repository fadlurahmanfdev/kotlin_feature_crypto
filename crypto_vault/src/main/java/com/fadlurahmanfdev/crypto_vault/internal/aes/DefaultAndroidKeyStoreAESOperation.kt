package com.fadlurahmanfdev.crypto_vault.internal.aes

import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESBlockMode
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.domain.contracts.AndroidKeyStoreAESOperation
import com.fadlurahmanfdev.crypto_vault.domain.models.EncryptedData
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

internal class DefaultAndroidKeyStoreAESOperation : AndroidKeyStoreAESOperation {
    companion object {
        const val GCM_TAG_LENGTH_BITS = 128

        fun create(): AndroidKeyStoreAESOperation {
            return DefaultAndroidKeyStoreAESOperation()
        }
    }

    override fun encrypt(
        transformation: String,
        secretKey: SecretKey,
        plainText: ByteArray,
    ): EncryptedData {
        try {
            val cipher = Cipher.getInstance(transformation)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return EncryptedData(
                text = cipher.doFinal(plainText),
                iv = cipher.iv,
            )
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    throw CryptoVaultExceptionCodes.keyPermanentlyInvalidated(
                        message = "Android Keystore key is permanently invalidated and must be regenerated",
                        cause = e,
                    )
                } else if (e is UserNotAuthenticatedException) {
                    throw CryptoVaultExceptionCodes.userNotAuthenticated(
                        message = "User must authenticate before using this Android Keystore key",
                        cause = e,
                    )
                }
            }
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to encrypt with Android Keystore AES key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun decrypt(
        transformation: String,
        secretKey: SecretKey,
        encrypted: ByteArray,
        iv: ByteArray,
    ): ByteArray {
        try {
            val algorithmParameterSpec = when (val blockMode = transformation.split("/")[1]) {
                CryptoVaultAESBlockMode.GCM.value -> GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
                CryptoVaultAESBlockMode.CBC.value -> IvParameterSpec(iv)
                else -> throw CryptoVaultExceptionCodes.invalidBlockMode(
                    message = "Parameter with specific block mode: $blockMode is not found",
                )
            }
            val cipher = Cipher.getInstance(transformation)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec)
            return cipher.doFinal(encrypted)
        } catch (e: AEADBadTagException) {
            throw CryptoVaultExceptionCodes.integrityCheckFailed(
                message = "Ciphertext or IV was modified, or does not belong to this key",
                cause = e,
            )
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    throw CryptoVaultExceptionCodes.keyPermanentlyInvalidated(
                        message = "Android Keystore key is permanently invalidated and must be regenerated",
                        cause = e,
                    )
                } else if (e is UserNotAuthenticatedException) {
                    throw CryptoVaultExceptionCodes.userNotAuthenticated(
                        message = "User must authenticate before using this Android Keystore key",
                        cause = e,
                    )
                }
            }

            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to decrypt with Android Keystore AES key: ${e.message}",
                cause = e,
            )
        }
    }
}