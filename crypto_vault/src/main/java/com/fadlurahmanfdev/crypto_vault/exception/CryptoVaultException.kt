package com.fadlurahmanfdev.crypto_vault.exception

/**
 * Domain exception thrown by CryptoVault public APIs.
 *
 * @param code Machine-readable error identifier.
 * @param message Human-readable error description.
 * @param cause Optional underlying failure.
 */
data class CryptoVaultException(
    val code: String,
    override val message: String? = null,
    override val cause: Throwable? = null,
) : Throwable(message, cause)
