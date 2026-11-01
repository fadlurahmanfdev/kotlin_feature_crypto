package com.fadlurahmanfdev.crypto_vault.internal

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.domain.contracts.KeyManager
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.SecretKey

internal class DefaultKeyManager: KeyManager {
    companion object {
        const val KEY_PROVIDER = "AndroidKeyStore"

        fun create() : KeyManager {
            return DefaultKeyManager()
        }
    }
    private fun keyStoreInstance() = KeyStore.getInstance(KEY_PROVIDER)

    @RequiresApi(Build.VERSION_CODES.P)
    override fun isSupportStrongBox(context: Context): Boolean {
        return context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }

    override fun getSecretKey(keyStoreAlias: String): SecretKey {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getKey(keyStoreAlias, null) as SecretKey
    }

    override fun getKeyPair(keyStoreAlias: String): KeyPair {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        val privateKey = keyStore.getKey(keyStoreAlias, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(keyStoreAlias)?.publicKey

        if (privateKey == null || publicKey == null) {
            throw CryptoVaultExceptionCodes.keyNotFound(
                message = "Android Keystore key pair was not found for alias \"$keyStoreAlias\"",
            )
        }

        return KeyPair(publicKey, privateKey)
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