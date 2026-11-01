package com.fadlurahmanfdev.crypto_vault

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAESAndroidKeyStore
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultAESTest {
    private lateinit var softwareAes: CryptoVaultAES
    private lateinit var keyStoreAes: CryptoVaultAESAndroidKeyStore

    @Before
    fun setUp() {
        softwareAes = CryptoVaultAES.create()
        keyStoreAes = CryptoVaultAESAndroidKeyStore.create()
    }

    @Test
    fun software_generate_secret_key_success() {
        val key = softwareAes.generateKey()
        assertEquals("AES", key.algorithm)
        assertEquals(32, key.encoded.size)
    }

    @Test
    fun software_encrypt_decrypt_gcm_round_trip_success() {
        val key = softwareAes.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()
        val encryptedData = softwareAes.encrypt(secretKey = key, plainText = plainTextBytes)
        val decrypted = softwareAes.decrypt(
            secretKey = key,
            encryptedBytes = encryptedData.encryptedBytes,
            ivBytes = encryptedData.ivBytes,
        )
        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun software_encrypt_decrypt_cbc_pkcs7_with_custom_iv_success() {
        val key = softwareAes.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()
        val ivParameterSpec = softwareAes.generateIvParameterSpec()
        val encryptedBytes = softwareAes.encrypt(
            secretKey = key,
            plainTextBytes = plainTextBytes,
            blockMode = "CBC",
            padding = "PKCS7Padding",
            algorithmParameterSpec = ivParameterSpec,
        )
        val decrypted = softwareAes.decrypt(
            secretKey = key,
            encryptedBytes = encryptedBytes,
            blockMode = "CBC",
            padding = "PKCS7Padding",
            algorithmParameterSpec = ivParameterSpec,
        )
        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun keystore_generate_secret_key_success() {

        val keystoreAlias = "example_keystore_aes_${System.currentTimeMillis()}"
        keyStoreAes.deleteKey(keystoreAlias)
        val key = keyStoreAes.generateKey(keyStoreAlias = keystoreAlias)
        assertEquals("AES", key.algorithm)
    }

    @Test
    fun keystore_encrypt_decrypt_gcm_round_trip_success() {

        val alias = "aes_alias_for_test_${System.currentTimeMillis()}"
        keyStoreAes.deleteKey(alias)
        val key = keyStoreAes.generateKey(keyStoreAlias = alias)
        val plainTextBytes = "Passw0rd!".toByteArray()
        val encryptedData = keyStoreAes.encrypt(secretKey = key, plainTextBytes = plainTextBytes)
        assertTrue(encryptedData.encryptedBytes.isNotEmpty())
        assertTrue(encryptedData.ivBytes.isNotEmpty())

        val loadedKey = keyStoreAes.getKey(alias)
        assertNotNull(loadedKey)
        val decrypted = keyStoreAes.decrypt(
            secretKey = loadedKey!!,
            encryptedBytes = encryptedData.encryptedBytes,
            ivBytes = encryptedData.ivBytes,
        )
        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun keystore_encrypt_decrypt_cbc_pkcs7_round_trip_success() {

        val alias = "aes_cbc_alias_${System.currentTimeMillis()}"
        keyStoreAes.deleteKey(alias)
        val key = keyStoreAes.generateKey(
            keyStoreAlias = alias,
            blockMode = "CBC",
            padding = "PKCS7Padding",
        )
        val plainTextBytes = "Passw0rd!".toByteArray()
        val encryptedData = keyStoreAes.encrypt(
            secretKey = key,
            plainTextBytes = plainTextBytes,
            blockMode = "CBC",
            padding = "PKCS7Padding",
        )
        val decrypted = keyStoreAes.decrypt(
            secretKey = key,
            encryptedBytes = encryptedData.encryptedBytes,
            ivBytes = encryptedData.ivBytes,
            blockMode = "CBC",
            padding = "PKCS7Padding",
        )
        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun keystore_decrypt_tampered_ciphertext_throws_integrity_check_failed() {

        val alias = "aes_integrity_${System.currentTimeMillis()}"
        keyStoreAes.deleteKey(alias)
        val key = keyStoreAes.generateKey(keyStoreAlias = alias)
        val encryptedData = keyStoreAes.encrypt(
            secretKey = key,
            plainTextBytes = "Passw0rd!".toByteArray(),
        )
        val tampered = encryptedData.encryptedBytes.copyOf().also { it[0] = (it[0] + 1).toByte() }

        try {
            keyStoreAes.decrypt(
                secretKey = key,
                encryptedBytes = tampered,
                ivBytes = encryptedData.ivBytes,
            )
            fail("Expected CryptoVaultException")
        } catch (e: CryptoVaultException) {
            assertEquals("INTEGRITY_CHECK_FAILED", e.code)
        }
    }

    @Test
    fun get_key_from_android_keystore_returns_null_when_missing() {

        val missingAlias = "missing_aes_alias_${System.currentTimeMillis()}"
        assertNull(keyStoreAes.getKey(missingAlias))
    }

    @Test
    fun get_key_from_android_keystore_returns_key_when_present() {

        val alias = "aes_get_key_test_${System.currentTimeMillis()}"
        keyStoreAes.deleteKey(alias)
        keyStoreAes.generateKey(keyStoreAlias = alias)
        assertNotNull(keyStoreAes.getKey(alias))
        assertTrue(keyStoreAes.isKeyExist(alias))
    }

    @Test
    fun generate_key_with_blank_alias_throws_invalid_key_alias() {

        try {
            keyStoreAes.generateKey(keyStoreAlias = "  ")
            fail("Expected CryptoVaultException")
        } catch (e: CryptoVaultException) {
            assertEquals("INVALID_KEY_ALIAS", e.code)
        }
    }

    @Test
    fun is_support_strong_box_does_not_crash_on_api_28_plus() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return

        val context = InstrumentationRegistry.getInstrumentation().targetContext
        keyStoreAes.isSupportStrongBox(context)
    }
}
