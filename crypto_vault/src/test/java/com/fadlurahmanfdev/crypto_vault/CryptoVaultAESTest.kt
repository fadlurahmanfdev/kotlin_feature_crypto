package com.fadlurahmanfdev.crypto_vault

import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.internal.aes.DefaultSoftwareAESOperation
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import javax.crypto.KeyGenerator

class CryptoVaultAESTest {

    private lateinit var cryptoVaultAES: CryptoVaultAES

    @Before
    fun setUp() {
        cryptoVaultAES = CryptoVaultAES.create()
    }

    @Test
    fun generateKey_default_returns_256_bit_aes_key() {
        val secretKey = cryptoVaultAES.generateKey()

        assertEquals("AES", secretKey.algorithm)
        assertEquals(32, secretKey.encoded.size)
    }

    @Test
    fun generateKey_with_128_bit_key_size_returns_16_byte_key() {
        val secretKey = cryptoVaultAES.generateKey(keySize = 128)

        assertEquals(16, secretKey.encoded.size)
    }

    @Test
    fun generateKey_returns_different_key_each_call() {
        val first = cryptoVaultAES.generateKey()
        val second = cryptoVaultAES.generateKey()

        assertFalse(first.encoded.contentEquals(second.encoded))
    }

    @Test
    fun generateKey_with_unsupported_key_size_throws_invalid_key_size() {
        val exception = assertThrows(CryptoVaultException::class.java) {
            cryptoVaultAES.generateKey(keySize = 64)
        }

        assertEquals("INVALID_KEY_SIZE", exception.code)
    }

    @Test
    fun generateKey_with_192_bit_key_size_throws_invalid_key_size() {
        val exception = assertThrows(CryptoVaultException::class.java) {
            cryptoVaultAES.generateKey(keySize = 192)
        }

        assertEquals("INVALID_KEY_SIZE", exception.code)
    }

    @Test
    fun generateKey_wraps_key_generator_failure_as_unknown() {
        val failure = IllegalStateException("provider unavailable")
        val cryptoVault = CryptoVaultAES(
            operation = DefaultSoftwareAESOperation(
                keyGeneratorFactory = { throw failure },
            ),
        )

        val exception = assertThrows(CryptoVaultException::class.java) {
            cryptoVault.generateKey()
        }

        assertEquals("UNKNOWN", exception.code)
        assertEquals(failure, exception.cause)
    }

    @Test
    fun encrypt_decrypt_gcm_with_generated_iv_round_trip() {
        val secretKey = cryptoVaultAES.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()

        val encryptedData = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            plainText = plainTextBytes,
        )
        val decrypted = cryptoVaultAES.decrypt(
            secretKey = secretKey,
            encryptedBytes = encryptedData.encryptedBytes,
            ivBytes = encryptedData.ivBytes,
        )

        assertTrue(encryptedData.encryptedBytes.isNotEmpty())
        assertTrue(encryptedData.ivBytes.isNotEmpty())
        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun encrypt_decrypt_gcm_with_custom_gcm_parameter_spec_round_trip() {
        val secretKey = cryptoVaultAES.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()
        val gcmParameterSpec = cryptoVaultAES.generateGCMParameterSpec()

        val encryptedBytes = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            plainTextBytes = plainTextBytes,
            algorithmParameterSpec = gcmParameterSpec,
        )
        val decrypted = cryptoVaultAES.decrypt(
            secretKey = secretKey,
            encryptedBytes = encryptedBytes,
            algorithmParameterSpec = gcmParameterSpec,
        )

        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun encrypt_decrypt_cbc_pkcs5_with_custom_iv_round_trip() {
        val secretKey = cryptoVaultAES.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()
        val ivParameterSpec = cryptoVaultAES.generateIvParameterSpec()

        val encryptedBytes = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            plainTextBytes = plainTextBytes,
            blockMode = "CBC",
            padding = "PKCS5Padding",
            algorithmParameterSpec = ivParameterSpec,
        )
        val decrypted = cryptoVaultAES.decrypt(
            secretKey = secretKey,
            encryptedBytes = encryptedBytes,
            blockMode = "CBC",
            padding = "PKCS5Padding",
            algorithmParameterSpec = ivParameterSpec,
        )

        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun decrypt_gcm_with_tampered_ciphertext_throws_integrity_check_failed() {
        val secretKey = cryptoVaultAES.generateKey()
        val encryptedData = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            plainText = "Passw0rd!".toByteArray(),
        )
        val tampered = encryptedData.encryptedBytes.copyOf().also { it[0] = (it[0] + 1).toByte() }

        val exception = assertThrows(CryptoVaultException::class.java) {
            cryptoVaultAES.decrypt(
                secretKey = secretKey,
                encryptedBytes = tampered,
                ivBytes = encryptedData.ivBytes,
            )
        }

        assertEquals("INTEGRITY_CHECK_FAILED", exception.code)
    }

    @Test
    fun parseKey_round_trip_with_exported_key_bytes() {
        val secretKey = cryptoVaultAES.generateKey()
        val parsed = cryptoVaultAES.parseKey(secretKey.encoded)
        val plainTextBytes = "hello".toByteArray()

        val encryptedData = cryptoVaultAES.encrypt(secretKey = parsed, plainText = plainTextBytes)
        val decrypted = cryptoVaultAES.decrypt(
            secretKey = cryptoVaultAES.parseKey(secretKey.encoded),
            encryptedBytes = encryptedData.encryptedBytes,
            ivBytes = encryptedData.ivBytes,
        )

        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun generateGCMParameterSpec_uses_requested_sizes() {
        val spec = cryptoVaultAES.generateGCMParameterSpec(ivSizeBytes = 12, tagLengthBits = 128)

        assertEquals(12, spec.iv.size)
        assertEquals(128, spec.tLen)
    }

    @Test
    fun generateKey_uses_aes_key_generator() {
        var requested = false
        val cryptoVault = CryptoVaultAES(
            operation = DefaultSoftwareAESOperation(
                keyGeneratorFactory = {
                    requested = true
                    KeyGenerator.getInstance("AES")
                },
            ),
        )

        cryptoVault.generateKey()

        assertTrue(requested)
    }
}
