package com.fadlurahmanfdev.crypto_vault.api.base

import android.util.Log
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultUtils
import java.security.KeyStore
import javax.crypto.Cipher

/**
 * Base vault with shared encoding helpers and Android Keystore key deletion.
 *
 * Extend this class or a subclass when you need reusable encode/decode helpers in a custom vault.
 */
abstract class BaseCryptoVault {
    /** Returns whether the device JCA provider supports [transformation]. */
    open fun isSupported(transformation: String): Boolean {
        return try {
            Cipher.getInstance(transformation)
            true
        } catch (e: Exception) {
            false
        }
    }

    /** Deletes a key entry from Android Keystore. Failures are logged and not rethrown. */
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

    /** Encodes [byte] as a Base64 string without line wrapping. */
    open fun encode(byte: ByteArray): String = CryptoVaultUtils.encode(byte)

    /** Decodes a Base64 [text] string into bytes. */
    open fun decode(text: String): ByteArray = CryptoVaultUtils.decode(text)

    /** Decodes Base64 [byte] content into bytes. */
    open fun decode(byte: ByteArray): ByteArray = CryptoVaultUtils.decode(byte)
}
