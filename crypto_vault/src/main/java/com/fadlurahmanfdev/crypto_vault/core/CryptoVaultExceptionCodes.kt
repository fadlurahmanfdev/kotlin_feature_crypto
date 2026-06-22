package com.fadlurahmanfdev.crypto_vault.core

import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException

internal object CryptoVaultExceptionCodes {
    fun strongBoxNotSupported(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = "STRONG_BOX_NOT_SUPPORTED",
            message = message,
            cause = cause,
        )

    fun unknown(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = "UNKNOWN",
            message = message,
            cause = cause,
        )
}
