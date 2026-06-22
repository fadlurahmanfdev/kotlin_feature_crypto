package com.fadlurahmanfdev.crypto_vault.core.exception

/**
 * Domain exception thrown by CryptoVault public APIs.
 *
 * Known [code] values:
 * - `STRONG_BOX_NOT_SUPPORTED` — StrongBox was requested but unavailable
 * - `UNKNOWN` — unexpected Keystore or crypto failure
 * - `UNSUPPORTED_EC_TRANSFORMATION` — unsupported EC encryption transformation
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
