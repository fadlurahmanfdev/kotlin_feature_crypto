package com.fadlurahmanfdev.crypto_vault

import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.internal.SoftwareKeyAESOperation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
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
    fun generateKey_with_192_bit_key_size_returns_24_byte_key() {
        val secretKey = cryptoVaultAES.generateKey(keySize = 192)

        assertEquals(24, secretKey.encoded.size)
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
    fun generateKey_requests_aes_key_generator_from_factory() {
        val keyGeneratorFactory = RecordingKeyGeneratorFactory()
        val cryptoVault = CryptoVaultAES(
            operation = SoftwareKeyAESOperation(keyGeneratorFactory = keyGeneratorFactory),
        )

        cryptoVault.generateKey()

        assertEquals(listOf("AES"), keyGeneratorFactory.requestedAlgorithms)
    }

    @Test
    fun generateKey_wraps_key_generator_failure_as_unknown() {
        val failure = IllegalStateException("provider unavailable")
        val cryptoVault = CryptoVaultAES(
            operation = SoftwareKeyAESOperation(
                keyGeneratorFactory = object : KeyGeneratorFactory {
                    override fun create(algorithm: String): KeyGenerator = throw failure
                },
            ),
        )

        val exception = assertThrows(CryptoVaultException::class.java) {
            cryptoVault.generateKey()
        }

        assertEquals("UNKNOWN", exception.code)
        assertSame(failure, exception.cause)
    }

    private class RecordingKeyGeneratorFactory : KeyGeneratorFactory {
        val requestedAlgorithms = mutableListOf<String>()

        override fun create(algorithm: String): KeyGenerator {
            requestedAlgorithms.add(algorithm)
            return KeyGenerator.getInstance(algorithm)
        }
    }
}
