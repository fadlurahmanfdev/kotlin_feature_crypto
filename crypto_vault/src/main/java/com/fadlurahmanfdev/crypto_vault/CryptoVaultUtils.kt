package com.fadlurahmanfdev.crypto_vault

import android.util.Base64

class CryptoVaultUtils {
    companion object {
         fun encode(byte: ByteArray): String {
            return Base64.encodeToString(byte, Base64.NO_WRAP)
        }

         fun decode(text: String): ByteArray {
            return Base64.decode(text.toByteArray(), Base64.NO_WRAP)
        }

         fun decode(byte: ByteArray): ByteArray {
            return Base64.decode(byte, Base64.NO_WRAP)
        }
    }
}