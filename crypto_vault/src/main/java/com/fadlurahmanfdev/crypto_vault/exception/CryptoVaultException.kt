package com.fadlurahmanfdev.crypto_vault.exception

data class CryptoVaultException(
    val code: String,
    override val message: String? = null,
) : Throwable(message)