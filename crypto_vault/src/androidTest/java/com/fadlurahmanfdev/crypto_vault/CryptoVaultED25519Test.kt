package com.fadlurahmanfdev.crypto_vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.api.ed25519.CryptoVaultED25519
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultED25519Test {
    private lateinit var cryptoVaultED25519: CryptoVaultED25519

    @Before
    fun setUp() {
        cryptoVaultED25519 = CryptoVaultED25519.create()
    }

    @Test
    fun generate_key_success_is_not_empty() {
        val key = cryptoVaultED25519.generateKey()
        assertTrue(key.publicKeyBytes.isNotEmpty())
        assertTrue(key.privateKeyBytes.isNotEmpty())
    }

    @Test
    fun generate_and_verify_signature() {
        val plainTextBytes = "Plain Signature Text".toByteArray()
        val key = cryptoVaultED25519.generateKey()
        val signatureBytes = cryptoVaultED25519.generateSignature(
            privateKeyBytes = key.privateKeyBytes,
            plainTextBytes = plainTextBytes,
        )
        assertTrue(signatureBytes.isNotEmpty())
        assertTrue(
            cryptoVaultED25519.verifySignature(
                publicKeyBytes = key.publicKeyBytes,
                signatureBytes = signatureBytes,
                plainTextBytes = plainTextBytes,
            ),
        )
    }

    @Test
    fun verify_signature_returns_false_for_invalid_signature() {
        val key = cryptoVaultED25519.generateKey()
        assertFalse(
            cryptoVaultED25519.verifySignature(
                publicKeyBytes = key.publicKeyBytes,
                plainTextBytes = "Plain Signature Text".toByteArray(),
                signatureBytes = key.privateKeyBytes,
            ),
        )
    }

    @Test
    fun verify_tampered_signature_returns_false() {
        val plainTextBytes = "Plain Signature Text".toByteArray()
        val key = cryptoVaultED25519.generateKey()
        val signatureBytes = cryptoVaultED25519.generateSignature(
            privateKeyBytes = key.privateKeyBytes,
            plainTextBytes = plainTextBytes,
        )
        val tamperedBytes = signatureBytes.copyOf().also { it[0] = (it[0] + 1).toByte() }

        assertFalse(
            cryptoVaultED25519.verifySignature(
                publicKeyBytes = key.publicKeyBytes,
                plainTextBytes = plainTextBytes,
                signatureBytes = tamperedBytes,
            ),
        )
    }
}
