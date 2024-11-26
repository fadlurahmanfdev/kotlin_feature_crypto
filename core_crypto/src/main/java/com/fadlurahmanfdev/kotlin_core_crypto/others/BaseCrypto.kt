package com.fadlurahmanfdev.kotlin_core_crypto.others

import android.util.Base64
import javax.crypto.Cipher

abstract class BaseCrypto {
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