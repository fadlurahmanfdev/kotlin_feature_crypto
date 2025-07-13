package com.fadlurahmanfdev.kotlin_feature_crypto.exception

data class CryptoVaultException(
    val code: String,
    override val message: String? = null,
) : Throwable(message)