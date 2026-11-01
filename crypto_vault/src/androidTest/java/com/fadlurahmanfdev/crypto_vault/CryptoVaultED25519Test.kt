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
        assertTrue(key.encodedPublicKey.isNotEmpty())
        assertTrue(key.encodedPrivateKey.isNotEmpty())
    }

    @Test
    fun generate_and_verify_signature() {
        val plainText = "Plain Signature Text".toByteArray()
        val key = cryptoVaultED25519.generateKey()
        val signature = cryptoVaultED25519.generateSignature(
            encodedPrivateKey = key.encodedPrivateKey,
            plainText = plainText,
        )
        assertTrue(signature.isNotEmpty())
        assertTrue(
            cryptoVaultED25519.verifySignature(
                encodedPublicKey = key.encodedPublicKey,
                signature = signature,
                plainText = plainText,
            ),
        )
    }

    @Test
    fun verify_signature_returns_false_for_invalid_signature() {
        val key = cryptoVaultED25519.generateKey()
        assertFalse(
            cryptoVaultED25519.verifySignature(
                encodedPublicKey = key.encodedPublicKey,
                plainText = "Plain Signature Text".toByteArray(),
                signature = key.encodedPrivateKey,
            ),
        )
    }

    @Test
    fun verify_tampered_signature_returns_false() {
        val plainText = "Plain Signature Text".toByteArray()
        val key = cryptoVaultED25519.generateKey()
        val signature = cryptoVaultED25519.generateSignature(
            encodedPrivateKey = key.encodedPrivateKey,
            plainText = plainText,
        )
        val tampered = signature.copyOf().also { it[0] = (it[0] + 1).toByte() }

        assertFalse(
            cryptoVaultED25519.verifySignature(
                encodedPublicKey = key.encodedPublicKey,
                plainText = plainText,
                signature = tampered,
            ),
        )
    }
}
