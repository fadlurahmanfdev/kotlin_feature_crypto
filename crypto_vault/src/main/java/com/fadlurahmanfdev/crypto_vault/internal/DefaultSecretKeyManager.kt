package com.fadlurahmanfdev.crypto_vault.internal

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.domain.contracts.SecretKeyManager
import java.security.KeyStore
import javax.crypto.SecretKey

internal class DefaultSecretKeyManager: SecretKeyManager {
    companion object {
        const val KEY_PROVIDER = "AndroidKeyStore"

        fun create() : SecretKeyManager {
            return DefaultSecretKeyManager()
        }
    }
    private fun keyStoreInstance() = KeyStore.getInstance(KEY_PROVIDER)

    @RequiresApi(Build.VERSION_CODES.P)
    override fun isSupportStrongBox(context: Context): Boolean {
        return context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }

    override fun getKey(keyStoreAlias: String): SecretKey {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getKey(keyStoreAlias, null) as SecretKey
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

}