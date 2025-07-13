package com.fadlurahmanfdev.kotlin_feature_crypto.constant

import com.fadlurahmanfdev.kotlin_feature_crypto.exception.CryptoVaultException

object CryptoVaultExceptionConstant {
    val STRONG_BOX_NOT_SUPPORTED = CryptoVaultException(code = "STRONG_BOX_NOT_SUPPORTED")
    val UNKNOWN = CryptoVaultException(code = "UNKNOWN")
}