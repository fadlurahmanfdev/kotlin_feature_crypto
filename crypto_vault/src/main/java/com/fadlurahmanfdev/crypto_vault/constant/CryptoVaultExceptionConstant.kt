package com.fadlurahmanfdev.crypto_vault.constant

import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException

object CryptoVaultExceptionConstant {
    val STRONG_BOX_NOT_SUPPORTED = CryptoVaultException(code = "STRONG_BOX_NOT_SUPPORTED")
    val UNKNOWN = CryptoVaultException(code = "UNKNOWN")
}