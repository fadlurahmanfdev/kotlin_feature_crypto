package com.fadlurahmanfdev.crypto_vault.core

import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException

/**
 * Centralized machine-readable [CryptoVaultException.code] values and factory helpers.
 *
 * Prefer throwing via these factories instead of constructing [CryptoVaultException]
 * with inline string codes.
 */
internal object CryptoVaultExceptionCodes {
    const val STRONG_BOX_NOT_SUPPORTED = "STRONG_BOX_NOT_SUPPORTED"
    const val UNKNOWN = "UNKNOWN"
    const val UNSUPPORTED_EC_TRANSFORMATION = "UNSUPPORTED_EC_TRANSFORMATION"
    const val INVALID_KEY_SIZE = "INVALID_KEY_SIZE"
    const val INVALID_KEY_ALIAS = "INVALID_KEY_ALIAS"
    const val KEY_PERMANENTLY_INVALIDATED = "KEY_PERMANENTLY_INVALIDATED"
    const val USER_NOT_AUTHENTICATED = "USER_NOT_AUTHENTICATED"
    const val INTEGRITY_CHECK_FAILED = "INTEGRITY_CHECK_FAILED"
    const val KEY_TYPE_MISMATCH = "KEY_TYPE_MISMATCH"
    const val INVALID_BLOCK_MODE = "INVALID_BLOCK_MODE"

    fun strongBoxNotSupported(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = STRONG_BOX_NOT_SUPPORTED,
            message = message,
            cause = cause,
        )

    fun unknown(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = UNKNOWN,
            message = message,
            cause = cause,
        )

    fun unsupportedEcTransformation(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = UNSUPPORTED_EC_TRANSFORMATION,
            message = message,
            cause = cause,
        )

    fun invalidKeySize(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = INVALID_KEY_SIZE,
            message = message,
            cause = cause,
        )

    fun invalidKeyAlias(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = INVALID_KEY_ALIAS,
            message = message,
            cause = cause,
        )

    fun keyPermanentlyInvalidated(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = KEY_PERMANENTLY_INVALIDATED,
            message = message,
            cause = cause,
        )

    fun userNotAuthenticated(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = USER_NOT_AUTHENTICATED,
            message = message,
            cause = cause,
        )

    fun integrityCheckFailed(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = INTEGRITY_CHECK_FAILED,
            message = message,
            cause = cause,
        )

    fun keyTypeMismatch(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = KEY_TYPE_MISMATCH,
            message = message,
            cause = cause,
        )

    fun invalidBlockMode(message: String?, cause: Throwable? = null): CryptoVaultException =
        CryptoVaultException(
            code = INVALID_BLOCK_MODE,
            message = message,
            cause = cause,
        )
}
