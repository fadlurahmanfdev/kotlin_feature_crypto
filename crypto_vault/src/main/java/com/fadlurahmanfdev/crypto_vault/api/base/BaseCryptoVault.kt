package com.fadlurahmanfdev.crypto_vault.api.base

import android.util.Log
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultUtils
import java.security.KeyStore
import javax.crypto.Cipher

/**
 * Base vault with shared encoding helpers and Android Keystore key deletion.
 */
abstract class BaseCryptoVault {
    open fun isSupported(transformation: String): Boolean {
        return try {
            Cipher.getInstance(transformation)
            true
        } catch (e: Exception) {
            false
        }
    }

    open fun deleteKey(keystoreAlias: String) {
        try {
            val keystore = KeyStore.getInstance("AndroidKeyStore")
            keystore.load(null)
            keystore.deleteEntry(keystoreAlias)
            Log.i(
                this::class.java.simpleName,
                "CryptoVault-LOG %%% successfully delete key from AndroidKeyStore",
            )
        } catch (e: Throwable) {
            Log.e(
                this::class.java.simpleName,
                "CryptoVault-LOG %%% failed delete key from AndroidKeyStore",
                e,
            )
        }
    }

    open fun encode(byte: ByteArray): String = CryptoVaultUtils.encode(byte)

    open fun decode(text: String): ByteArray = CryptoVaultUtils.decode(text)

    open fun decode(byte: ByteArray): ByteArray = CryptoVaultUtils.decode(byte)
}
