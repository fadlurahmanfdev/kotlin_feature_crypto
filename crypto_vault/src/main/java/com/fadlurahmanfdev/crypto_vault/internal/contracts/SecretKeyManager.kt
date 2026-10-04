package com.fadlurahmanfdev.crypto_vault.internal.contracts

import javax.crypto.SecretKey

internal interface SecretKeyManager {
    fun generate(
        algorithm: String,
        keySize: Int,
    ): SecretKey

    fun parse(key: ByteArray, algorithm: String): SecretKey
}