package com.fadlurahmanfdev.crypto_vault

import com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSA
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.internal.rsa.DefaultSoftwareRSAOperation
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyPairGenerator

class CryptoVaultRSATest {

    private lateinit var cryptoVaultRSA: CryptoVaultRSA

    @Before
    fun setUp() {
        cryptoVaultRSA = CryptoVaultRSA.create()
    }

    @Test
    fun generateKey_default_returns_2048_bit_rsa_key() {
        val keyPair = cryptoVaultRSA.generateKey()

        assertEquals("RSA", keyPair.private.algorithm)
        assertEquals("RSA", keyPair.public.algorithm)
        assertTrue(keyPair.private.encoded.isNotEmpty())
        assertTrue(keyPair.public.encoded.isNotEmpty())
    }

    @Test
    fun generateKey_with_unsupported_key_size_throws_invalid_key_size() {
        val exception = assertThrows(CryptoVaultException::class.java) {
            cryptoVaultRSA.generateKey(keySize = 1024)
        }

        assertEquals("INVALID_KEY_SIZE", exception.code)
    }

    @Test
    fun generateKey_wraps_key_pair_generator_failure_as_unknown() {
        val failure = IllegalStateException("provider unavailable")
        val cryptoVault = CryptoVaultRSA(
            operation = DefaultSoftwareRSAOperation(
                keyPairGeneratorFactory = { throw failure },
            ),
        )

        val exception = assertThrows(CryptoVaultException::class.java) {
            cryptoVault.generateKey()
        }

        assertEquals("UNKNOWN", exception.code)
        assertEquals(failure, exception.cause)
    }

    @Test
    fun encrypt_decrypt_oaep_sha256_round_trip() {
        val keyPair = cryptoVaultRSA.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()

        val encryptedBytes = cryptoVaultRSA.encrypt(
            publicKey = keyPair.public,
            plainTextBytes = plainTextBytes,
        )
        val decrypted = cryptoVaultRSA.decrypt(
            privateKey = keyPair.private,
            encryptedBytes = encryptedBytes,
        )

        assertTrue(encryptedBytes.isNotEmpty())
        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun sign_verify_sha256_with_rsa_round_trip() {
        val keyPair = cryptoVaultRSA.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()

        val signatureBytes = cryptoVaultRSA.sign(
            privateKey = keyPair.private,
            plainTextBytes = plainTextBytes,
        )
        val verified = cryptoVaultRSA.verify(
            publicKey = keyPair.public,
            signatureBytes = signatureBytes,
            plainTextBytes = plainTextBytes,
        )

        assertTrue(signatureBytes.isNotEmpty())
        assertTrue(verified)
    }

    @Test
    fun verify_tampered_signature_returns_false() {
        val keyPair = cryptoVaultRSA.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()
        val signatureBytes = cryptoVaultRSA.sign(
            privateKey = keyPair.private,
            plainTextBytes = plainTextBytes,
        )
        val tampered = signatureBytes.copyOf().also { it[0] = (it[0] + 1).toByte() }

        val verified = cryptoVaultRSA.verify(
            publicKey = keyPair.public,
            signatureBytes = tampered,
            plainTextBytes = plainTextBytes,
        )

        assertFalse(verified)
    }

    @Test
    fun parse_public_and_private_key_round_trip() {
        val keyPair = cryptoVaultRSA.generateKey()
        val publicKey = cryptoVaultRSA.parsePublicKey(keyPair.public.encoded)
        val privateKey = cryptoVaultRSA.parsePrivateKey(keyPair.private.encoded)
        val plainTextBytes = "hello".toByteArray()

        val encryptedBytes = cryptoVaultRSA.encrypt(publicKey = publicKey, plainTextBytes = plainTextBytes)
        val decrypted = cryptoVaultRSA.decrypt(privateKey = privateKey, encryptedBytes = encryptedBytes)

        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun generateKey_uses_rsa_key_pair_generator() {
        var requested = false
        val cryptoVault = CryptoVaultRSA(
            operation = DefaultSoftwareRSAOperation(
                keyPairGeneratorFactory = {
                    requested = true
                    KeyPairGenerator.getInstance("RSA")
                },
            ),
        )

        cryptoVault.generateKey()

        assertTrue(requested)
    }
}
