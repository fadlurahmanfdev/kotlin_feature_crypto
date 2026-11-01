package com.fadlurahmanfdev.crypto_vault

import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

class CryptoVaultExceptionTest {

    @Test
    fun exception_contains_code_message_and_cause() {
        val cause = IllegalStateException("root cause")
        val exception = CryptoVaultExceptionCodes.strongBoxNotSupported(
            message = "StrongBox unavailable",
            cause = cause,
        )

        assertEquals(CryptoVaultExceptionCodes.STRONG_BOX_NOT_SUPPORTED, exception.code)
        assertEquals("StrongBox unavailable", exception.message)
        assertSame(cause, exception.cause)
    }

    @Test
    fun exception_defaults_message_and_cause_to_null() {
        val exception = CryptoVaultException(code = CryptoVaultExceptionCodes.UNKNOWN)

        assertEquals(CryptoVaultExceptionCodes.UNKNOWN, exception.code)
        assertEquals(null, exception.message)
        assertEquals(null, exception.cause)
    }

    @Test
    fun exception_codes_factories_use_expected_constants() {
        assertEquals(
            CryptoVaultExceptionCodes.UNSUPPORTED_EC_TRANSFORMATION,
            CryptoVaultExceptionCodes.unsupportedEcTransformation("msg").code,
        )
        assertEquals(
            CryptoVaultExceptionCodes.INVALID_KEY_SIZE,
            CryptoVaultExceptionCodes.invalidKeySize("msg").code,
        )
        assertEquals(
            CryptoVaultExceptionCodes.INVALID_KEY_ALIAS,
            CryptoVaultExceptionCodes.invalidKeyAlias("msg").code,
        )
        assertEquals(
            CryptoVaultExceptionCodes.KEY_PERMANENTLY_INVALIDATED,
            CryptoVaultExceptionCodes.keyPermanentlyInvalidated("msg").code,
        )
        assertEquals(
            CryptoVaultExceptionCodes.USER_NOT_AUTHENTICATED,
            CryptoVaultExceptionCodes.userNotAuthenticated("msg").code,
        )
        assertEquals(
            CryptoVaultExceptionCodes.INTEGRITY_CHECK_FAILED,
            CryptoVaultExceptionCodes.integrityCheckFailed("msg").code,
        )
        assertEquals(
            CryptoVaultExceptionCodes.KEY_TYPE_MISMATCH,
            CryptoVaultExceptionCodes.keyTypeMismatch("msg").code,
        )
        assertEquals(
            CryptoVaultExceptionCodes.KEY_NOT_FOUND,
            CryptoVaultExceptionCodes.keyNotFound("msg").code,
        )
        assertEquals(
            CryptoVaultExceptionCodes.INVALID_BLOCK_MODE,
            CryptoVaultExceptionCodes.invalidBlockMode("msg").code,
        )
        assertEquals(
            CryptoVaultExceptionCodes.UNKNOWN,
            CryptoVaultExceptionCodes.unknown("msg").code,
        )
    }
}
