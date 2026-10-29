package com.fadlurahmanfdev.crypto_vault.internal

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.internal.contracts.KeyStoreKeyPairManager
import java.security.KeyPair
import java.security.KeyPairGenerator

internal class DefaultECDHAndroidKeyStoreKeyPairManager : KeyStoreKeyPairManager {
    companion object {
        const val KEY_PROVIDER = "AndroidKeyStore"

        fun create(): KeyStoreKeyPairManager {
            return DefaultECDHAndroidKeyStoreKeyPairManager()
        }
    }

    @RequiresApi(Build.VERSION_CODES.P)
    override fun isSupportStrongBox(context: Context): Boolean {
        return context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }

    @RequiresApi(Build.VERSION_CODES.S)
    override fun generateKey(
        keyStoreAlias: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit
    ): KeyPair {
        val purposes =
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_AGREE_KEY
        val parameterSpec = KeyGenParameterSpec.Builder(keyStoreAlias, purposes).apply {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setIsStrongBoxBacked(strongBoxBacked)
        }
            .apply(keyGenParameterSpecBuilder)
            .build()

        try {
            val keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEY_PROVIDER)
            keyPairGenerator.initialize(parameterSpec)
            return keyPairGenerator.generateKeyPair()
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException) {
                throw CryptoVaultExceptionCodes.strongBoxNotSupported(e.message, e)
            }

            throw CryptoVaultExceptionCodes.unknown(e.message, e)
        }
    }

}