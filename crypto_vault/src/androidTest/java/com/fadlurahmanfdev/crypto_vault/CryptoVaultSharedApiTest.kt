package com.fadlurahmanfdev.crypto_vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESBlockMode
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESEncryptionPadding
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultSharedApiTest {

    private lateinit var cryptoVaultAES: CryptoVaultAES

    @Before
    fun setUp() {
        cryptoVaultAES = CryptoVaultAES()
    }

    @Test
    fun isSupported_returns_true_for_valid_aes_transformation() {
        val transformation = "${CryptoVaultAlgorithm.AES}/${CryptoVaultAESBlockMode.GCM}/${CryptoVaultAESEncryptionPadding.NoPadding}"
        assertTrue(cryptoVaultAES.isSupported(transformation))
    }

    @Test
    fun isSupported_returns_false_for_invalid_transformation() {
        assertFalse(cryptoVaultAES.isSupported("INVALID/TRANSFORMATION/PADDING"))
    }

    @Test
    fun encode_and_decode_string_roundtrip() {
        val original = "crypto-vault-test-payload"
        val encoded = cryptoVaultAES.encode(original.toByteArray())
        val decoded = String(cryptoVaultAES.decode(encoded))
        assertEquals(original, decoded)
    }

    @Test
    fun encode_and_decode_byte_array_roundtrip() {
        val original = byteArrayOf(1, 2, 3, 4, 5)
        val encoded = cryptoVaultAES.encode(original)
        assertArrayEquals(original, cryptoVaultAES.decode(encoded))
    }

    @Test
    fun deleteKey_does_not_throw_for_missing_alias() {
        cryptoVaultAES.deleteKey("non_existent_alias_${System.currentTimeMillis()}")
    }
}
