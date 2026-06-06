package com.fadlurahmanfdev.crypto_vault.internal

import android.util.Base64

internal object CryptoVaultUtils {
    fun encode(byte: ByteArray): String = Base64.encodeToString(byte, Base64.NO_WRAP)

    fun decode(text: String): ByteArray = Base64.decode(text.toByteArray(), Base64.NO_WRAP)

    fun decode(byte: ByteArray): ByteArray = Base64.decode(byte, Base64.NO_WRAP)
}
