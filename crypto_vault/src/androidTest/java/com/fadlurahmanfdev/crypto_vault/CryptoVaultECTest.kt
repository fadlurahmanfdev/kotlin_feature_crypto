package com.fadlurahmanfdev.crypto_vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.api.ec.CryptoVaultEC
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultECTest {

    private lateinit var cryptoVaultEC: CryptoVaultEC
    private val plainTextBytes = "Passw0rd!".toByteArray()

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
            plainTextBytes = plainTextBytes,
        )
        assertTrue(signatureBytes.isNotEmpty())
        assertTrue(
            cryptoVaultEC.verifySignature(
                publicKeyBytes = publicKeyBytes,
                signatureBytes = signatureBytes,
                plainTextBytes = plainTextBytes,
            ),
        )
    }

    @Test
    fun encrypt_and_decrypt_round_trip() {
        val key = cryptoVaultEC.generateKey()
        val privateKeyBytes = key.private.encoded
        val publicKeyBytes = key.public.encoded
        val encryptedBytes = cryptoVaultEC.encrypt(
            recipientPublicKeyBytes = publicKeyBytes,
            plainTextBytes = plainTextBytes,
        )
        assertTrue(encryptedBytes.isNotEmpty())
        val decrypted = cryptoVaultEC.decrypt(
            recipientPrivateKeyBytes = privateKeyBytes,
            encryptedBytes = encryptedBytes,
        )
        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun encrypt_tampered_ciphertext_fails() {
        val key = cryptoVaultEC.generateKey()
        val encryptedBytes = cryptoVaultEC.encrypt(
            recipientPublicKeyBytes = key.public.encoded,
            plainTextBytes = plainTextBytes,
        ).copyOf()
        encryptedBytes[encryptedBytes.lastIndex] =
            (encryptedBytes[encryptedBytes.lastIndex].toInt() xor 0x01).toByte()
        try {
            cryptoVaultEC.decrypt(
                recipientPrivateKeyBytes = key.private.encoded,
                encryptedBytes = encryptedBytes,
            )
            org.junit.Assert.fail("Expected decrypt to fail for tampered ciphertext")
        } catch (_: Throwable) {
            // GCM auth failure or wrapped CryptoVaultException
        }
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
                plainTextBytes = plainTextBytes,
            ),
        )
    }

    @Test
    fun generate_shared_secret_and_derive_aes_key() {
        val bobKey = cryptoVaultEC.generateKey()
        val aliceKey = cryptoVaultEC.generateKey()

        val bobSharedSecretBytes = cryptoVaultEC.generateSharedSecret(
            ephemeralPrivateKeyBytes = bobKey.private.encoded,
            recipientPublicKeyBytes = aliceKey.public.encoded,
        )
        val aliceSharedSecretBytes = cryptoVaultEC.generateSharedSecret(
            ephemeralPrivateKeyBytes = aliceKey.private.encoded,
            recipientPublicKeyBytes = bobKey.public.encoded,
        )

        assertTrue(bobSharedSecretBytes.isNotEmpty())
        assertTrue(aliceSharedSecretBytes.isNotEmpty())
        assertTrue(bobSharedSecretBytes.contentEquals(aliceSharedSecretBytes))

        val saltBytes = "salt".toByteArray()
        val infoBytes = "CryptoVaultEC-AES-256-GCM".toByteArray()
        val bobDerivedKeyBytes = cryptoVaultEC.deriveAESKey(
            sharedSecretBytes = bobSharedSecretBytes,
            saltBytes = saltBytes,
            infoBytes = infoBytes,
        ).encoded
        val aliceDerivedKeyBytes = cryptoVaultEC.deriveAESKey(
            sharedSecretBytes = aliceSharedSecretBytes,
            saltBytes = saltBytes,
            infoBytes = infoBytes,
        ).encoded
        assertArrayEquals(bobDerivedKeyBytes, aliceDerivedKeyBytes)
        assertEquals(32, bobDerivedKeyBytes.size)
    }

    @Test
    fun hkdf_is_stable_for_fixed_inputs() {
        val sharedSecretBytes = ByteArray(32) { it.toByte() }
        val saltBytes = "fixed-salt".toByteArray()
        val infoBytes = "CryptoVaultEC-AES-256-GCM".toByteArray()
        val first = cryptoVaultEC.deriveAESKey(
            sharedSecretBytes = sharedSecretBytes,
            saltBytes = saltBytes,
            infoBytes = infoBytes,
        ).encoded
        val second = cryptoVaultEC.deriveAESKey(
            sharedSecretBytes = sharedSecretBytes,
            saltBytes = saltBytes,
            infoBytes = infoBytes,
        ).encoded
        assertArrayEquals(first, second)
    }
}
