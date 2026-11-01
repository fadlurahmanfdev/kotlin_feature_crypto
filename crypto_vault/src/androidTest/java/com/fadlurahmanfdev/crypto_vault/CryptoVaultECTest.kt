package com.fadlurahmanfdev.crypto_vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.api.ec.CryptoVaultEC
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultECTest {

    private lateinit var cryptoVaultEC: CryptoVaultEC
    private val plainText = "Passw0rd!"

    @Before
    fun setUp() {
        cryptoVaultEC = CryptoVaultEC.create()
    }

    @Test
    fun generate_key_success() {
        val key = cryptoVaultEC.generateKey()
        assertTrue(key.private.encoded.isNotEmpty())
        assertTrue(key.public.encoded.isNotEmpty())
    }

    @Test
    fun generate_and_verify_signature() {
        val key = cryptoVaultEC.generateKey()
        val privateKeyBytes = key.private.encoded
        val publicKeyBytes = key.public.encoded
        val signatureBytes = cryptoVaultEC.generateSignature(
            privateKeyBytes = privateKeyBytes,
            plainText = plainText,
        )
        assertTrue(signatureBytes.isNotEmpty())
        assertTrue(
            cryptoVaultEC.verifySignature(
                publicKeyBytes = publicKeyBytes,
                signatureBytes = signatureBytes,
                plainText = plainText,
            ),
        )
    }

    @Test
    fun encrypt_and_decrypt_round_trip() {
        val key = cryptoVaultEC.generateKey()
        val privateKeyBytes = key.private.encoded
        val publicKeyBytes = key.public.encoded
        val encryptedBytes = cryptoVaultEC.encrypt(
            publicKeyBytes = publicKeyBytes,
            plainText = plainText,
        )
        assertTrue(encryptedBytes.isNotEmpty())
        val decrypted = cryptoVaultEC.decrypt(
            privateKeyBytes = privateKeyBytes,
            encryptedBytes = encryptedBytes,
        )
        assertEquals(plainText, decrypted)
    }

    @Test
    fun verify_signature_returns_false_for_invalid_signature() {
        val key = cryptoVaultEC.generateKey()
        val publicKeyBytes = key.public.encoded
        val invalidSignatureBytes = ByteArray(64)
        assertFalse(
            cryptoVaultEC.verifySignature(
                publicKeyBytes = publicKeyBytes,
                signatureBytes = invalidSignatureBytes,
                plainText = plainText,
            ),
        )
    }

    @Test
    fun generate_shared_secret_and_derive_aes_key() {
        val bobKey = cryptoVaultEC.generateKey()
        val aliceKey = cryptoVaultEC.generateKey()

        val bobSharedSecretBytes = cryptoVaultEC.generateSharedSecret(
            ourPrivateKeyBytes = bobKey.private.encoded,
            otherPublicKeyBytes = aliceKey.public.encoded,
        )
        val aliceSharedSecretBytes = cryptoVaultEC.generateSharedSecret(
            ourPrivateKeyBytes = aliceKey.private.encoded,
            otherPublicKeyBytes = bobKey.public.encoded,
        )

        assertTrue(bobSharedSecretBytes.isNotEmpty())
        assertTrue(aliceSharedSecretBytes.isNotEmpty())
        assertTrue(bobSharedSecretBytes.contentEquals(aliceSharedSecretBytes))

        val bobDerivedKeyBytes =
            cryptoVaultEC.deriveAESKey(sharedSecretBytes = bobSharedSecretBytes)
        val aliceDerivedKeyBytes =
            cryptoVaultEC.deriveAESKey(sharedSecretBytes = aliceSharedSecretBytes)
        assertTrue(bobDerivedKeyBytes.contentEquals(aliceDerivedKeyBytes))
    }
}
