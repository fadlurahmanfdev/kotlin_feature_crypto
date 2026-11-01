package com.fadlurahmanfdev.crypto_vault.exception

/**
 * Domain exception thrown by CryptoVault public APIs.
 *
 * Known [code] values (see [com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes]):
 * - `STRONG_BOX_NOT_SUPPORTED` — StrongBox was requested but unavailable
 * - `UNKNOWN` — unexpected Keystore or crypto failure
 * - `UNSUPPORTED_EC_TRANSFORMATION` — unsupported EC encryption transformation
 * - `INVALID_KEY_SIZE` — requested key size is not supported by the algorithm
 * - `INVALID_KEY_ALIAS` — Android Keystore alias is blank
 * - `KEY_PERMANENTLY_INVALIDATED` — Android Keystore key was invalidated and must be regenerated
 * - `USER_NOT_AUTHENTICATED` — Android Keystore key requires user authentication first
 * - `INTEGRITY_CHECK_FAILED` — authenticated decryption failed (data modified or wrong key/IV)
 * - `KEY_TYPE_MISMATCH` — Android Keystore entry exists but is not the expected key algorithm/type
 * - `KEY_NOT_FOUND` — Android Keystore alias does not exist or key material is missing
 * - `INVALID_BLOCK_MODE` — AES transformation block mode is not supported
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
