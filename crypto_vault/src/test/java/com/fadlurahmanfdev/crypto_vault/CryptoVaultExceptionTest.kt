package com.fadlurahmanfdev.crypto_vault

import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

class CryptoVaultExceptionTest {

    @Test
    fun exception_contains_code_message_and_cause() {
        val cause = IllegalStateException("root cause")
        val exception = CryptoVaultException(
            code = "STRONG_BOX_NOT_SUPPORTED",
            message = "StrongBox unavailable",
            cause = cause,
        )

        assertEquals("STRONG_BOX_NOT_SUPPORTED", exception.code)
        assertEquals("StrongBox unavailable", exception.message)
        assertSame(cause, exception.cause)
    }

    @Test
    fun exception_defaults_message_and_cause_to_null() {
        val exception = CryptoVaultException(code = "UNKNOWN")

        assertEquals("UNKNOWN", exception.code)
        assertEquals(null, exception.message)
        assertEquals(null, exception.cause)
    }
}
