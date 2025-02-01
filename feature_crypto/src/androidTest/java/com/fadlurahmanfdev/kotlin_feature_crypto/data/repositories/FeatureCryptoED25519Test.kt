package com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.kotlin_feature_crypto.FeatureCryptoED25519
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FeatureCryptoED25519Test {
    lateinit var cryptoED25519Repository: CryptoED25519Repository

    @Before
    fun setUp() {
        cryptoED25519Repository = FeatureCryptoED25519()
    }

    @Test
    fun generate_key_success_is_not_empty() {
        val key = cryptoED25519Repository.generateKey()
        assertEquals(true, key.publicKey.isNotEmpty())
        assertEquals(true, key.privateKey.isNotEmpty())
    }

    @Test
    fun generate_and_verify_signature() {
        val plainSignatureText = "Plain Signature Text"
        val key = cryptoED25519Repository.generateKey()
        val signature = cryptoED25519Repository.generateSignature(
            encodedPrivateKey = key.privateKey,
            plainText = plainSignatureText,
        )
        assertEquals(true, signature != null)
        assertEquals(true, signature.isNotEmpty())
        val isVerify = cryptoED25519Repository.verifySignature(
            encodedPublicKey = key.publicKey,
            signature = signature!!,
            plainText = plainSignatureText,
        )
        assertEquals(true, isVerify)
    }
}