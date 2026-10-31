package com.fadlurahmanfdev.crypto_vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAESAndroidKeyStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultSharedApiTest {

    private lateinit var cryptoVault: CryptoVaultCustomKeyVault
    private lateinit var keyStoreAes: CryptoVaultAESAndroidKeyStore

    @Before
    fun setUp() {
        cryptoVault = CryptoVaultCustomKeyVault()
        keyStoreAes = CryptoVaultAESAndroidKeyStore.create()
    }

    @Test
    fun isSupported_returns_true_for_valid_aes_transformation() {
        assertTrue(cryptoVault.isSupported("AES/GCM/NoPadding"))
    }

    @Test
    fun isSupported_returns_false_for_invalid_transformation() {
        assertFalse(cryptoVault.isSupported("INVALID/TRANSFORMATION/PADDING"))
    }

    @Test
    fun encode_and_decode_string_roundtrip() {
        val original = "crypto-vault-test-payload"
        val encoded = cryptoVault.encode(original.toByteArray())
        val decoded = String(cryptoVault.decode(encoded))
        assertEquals(original, decoded)
    }

    @Test
    fun encode_and_decode_byte_array_roundtrip() {
        val original = byteArrayOf(1, 2, 3, 4, 5)
        val encoded = cryptoVault.encode(original)
        assertArrayEquals(original, cryptoVault.decode(encoded))
    }

    @Test
    fun deleteKey_does_not_throw_for_missing_alias() {
        keyStoreAes.deleteKey("non_existent_alias_${System.currentTimeMillis()}")
    }
}
