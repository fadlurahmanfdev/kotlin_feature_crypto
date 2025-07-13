package com.fadlurahmanfdev.kotlin_feature_crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultED25519Test {
    lateinit var cryptoVaultED25519: CryptoVaultED25519

    @Before
    fun setUp() {
        cryptoVaultED25519 = CryptoVaultED25519()
    }

    @Test
    fun generate_key_success_is_not_empty() {
        val key = cryptoVaultED25519.generateKey()
        assertEquals(true, key.publicKey.isNotEmpty())
        assertEquals(true, key.privateKey.isNotEmpty())
    }

    @Test
    fun generate_and_verify_signature() {
        val plainSignatureText = "Plain Signature Text"
        val key = cryptoVaultED25519.generateKey()
        val signature = cryptoVaultED25519.generateSignature(
            encodedPrivateKey = key.privateKey,
            plainText = plainSignatureText,
        )
        assertEquals(true, signature.isNotEmpty())
        val isVerify = cryptoVaultED25519.verifySignature(
            encodedPublicKey = key.publicKey,
            signature = signature,
            plainText = plainSignatureText,
        )
        assertEquals(true, isVerify)
    }
}