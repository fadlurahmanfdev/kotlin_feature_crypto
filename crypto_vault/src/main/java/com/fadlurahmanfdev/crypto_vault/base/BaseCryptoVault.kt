package com.fadlurahmanfdev.crypto_vault.base

import android.util.Log
import com.fadlurahmanfdev.crypto_vault.CryptoVaultUtils
import java.security.KeyStore
import javax.crypto.Cipher

abstract class BaseCryptoVault {
    /**
     * Check whether specified combination of algorithm, block mode, padding is supported.
     *
     * @param transformation transformation to check if supported
     *
     * @return [Boolean] is plain text verified with the given signature
     *
     * */
    fun isSupported(
        transformation: String,
    ): Boolean {
        try {
            Cipher.getInstance(transformation)
            return true
        } catch (e: Exception) {
            return false
        }
    }

    /**
     * Delete key from AndroidKeyStore
     *
     * @param keystoreAlias keystore alias of the key
     * */
    fun deleteKey(
        keystoreAlias: String,
    ) {
        try {
            val keystore = KeyStore.getInstance("AndroidKeyStore")
            keystore.load(null)
            keystore.deleteEntry(keystoreAlias)
            Log.i(
                this::class.java.simpleName,
                "CryptoVault-LOG %%% successfully delete key from AndroidKeyStore"
            )
        } catch (e: Throwable) {
            Log.e(
                this::class.java.simpleName,
                "CryptoVault-LOG %%% failed delete key from AndroidKeyStore",
                e
            )
        }
    }

    open fun encode(byte: ByteArray): String = CryptoVaultUtils.encode(byte)

    open fun decode(text: String): ByteArray = CryptoVaultUtils.decode(text)

    open fun decode(byte: ByteArray): ByteArray = CryptoVaultUtils.decode(byte)
}