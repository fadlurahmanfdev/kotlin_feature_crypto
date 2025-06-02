package com.fadlurahmanfdev.kotlin_feature_crypto.core.commons

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

abstract class BaseCryptoVault {
    @androidx.annotation.RequiresApi(Build.VERSION_CODES.M)
    fun generateKeyFromAndroidKeyStore(keyGenParameterSpec: KeyGenParameterSpec): SecretKey {
        val keystore = KeyStore.getInstance("AndroidKeyStore")
        keystore.load(null)
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGenerator.init(keyGenParameterSpec)
        val secretKey = keyGenerator.generateKey()
        return secretKey
    }

    fun getKeyFromAndroidKeyStore(keystoreAlias: String): SecretKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(keystoreAlias, null) as SecretKey?
    }

    /**
     * Check whether specified combination of algorithm, block mode, padding is supported.
     *
     * @param transformation transformation to check if supported
     *
     * @return [Boolean] is plain text verified with the given signature
     *
     * */
    fun isSupported(
        transformation:String,
    ): Boolean {
        try {
            Cipher.getInstance(transformation)
            return true
        } catch (e: Exception) {
            return false
        }
    }

    open fun encode(byte: ByteArray): String {
        return Base64.encodeToString(byte, Base64.NO_WRAP)
    }

    open fun decode(text: String): ByteArray {
        return Base64.decode(text.toByteArray(), Base64.NO_WRAP)
    }

    open fun decode(byte: ByteArray): ByteArray {
        return Base64.decode(byte, Base64.NO_WRAP)
    }
}