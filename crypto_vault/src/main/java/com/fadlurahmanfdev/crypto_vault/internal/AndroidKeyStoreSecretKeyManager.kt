package com.fadlurahmanfdev.crypto_vault.internal

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.domain.contracts.AndroidKeyStoreAESOperation
import com.fadlurahmanfdev.crypto_vault.internal.aes.DefaultAndroidKeyStoreAESOperation
import com.fadlurahmanfdev.crypto_vault.internal.contracts.KeyStoreSecretKeyManager
import java.security.KeyStore
import java.security.cert.Certificate
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

internal class AndroidKeyStoreSecretKeyManager : KeyStoreSecretKeyManager {

    companion object {
        const val KEY_PROVIDER = "AndroidKeyStore"
        const val GCM_TAG_LENGTH_BITS = 128
        val SUPPORTED_KEY_SIZES = setOf(128, 256)

        fun create() : AndroidKeyStoreAESOperation {
            return DefaultAndroidKeyStoreAESOperation()
        }
    }
    private fun keyStoreInstance() = KeyStore.getInstance(KEY_PROVIDER)

    @RequiresApi(Build.VERSION_CODES.P)
    override fun isSupportStrongBox(context: Context): Boolean {
        return context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }

    override fun generateKey(
        algorithm: String,
        keyStoreAlias: String,
        keySize: Int,
        blockMode: String,
        padding: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit
    ): SecretKey {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
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

                val keyGenerator = KeyGenerator.getInstance(algorithm, KEY_PROVIDER)
                keyGenerator.init(keyGenParameterSpec)
                return keyGenerator.generateKey()
            } else {
                throw CryptoVaultExceptionCodes.sdkNotSupported(
                    message = "Unable to generate secret key caused by sdk not supported",
                )
            }
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (e is StrongBoxUnavailableException) {
                    throw CryptoVaultExceptionCodes.strongBoxNotSupported(
                        message = "StrongBox is not available on this device",
                        cause = e,
                    )
                }
            }

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

    override fun getCertificateAlias(certificate: Certificate): String {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getCertificateAlias(certificate)
    }

    override fun getCertificate(keyStoreAlias: String): Certificate {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getCertificate(keyStoreAlias)
    }

    override fun getCertificateChain(keyStoreAlias: String): Array<Certificate> {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getCertificateChain(keyStoreAlias)
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