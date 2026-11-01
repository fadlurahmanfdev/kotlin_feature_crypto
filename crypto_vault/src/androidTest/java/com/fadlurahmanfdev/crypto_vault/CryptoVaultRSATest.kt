package com.fadlurahmanfdev.crypto_vault

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSA
import com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSAAndroidKeyStore
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultRSATest {
    private lateinit var softwareRsa: CryptoVaultRSA
    private lateinit var keyStoreRsa: CryptoVaultRSAAndroidKeyStore

    @Before
    fun setUp() {
        softwareRsa = CryptoVaultRSA.create()
        keyStoreRsa = CryptoVaultRSAAndroidKeyStore.create()
    }

    @Test
    fun software_generate_key_success() {
        val keyPair = softwareRsa.generateKey()
        assertEquals("RSA", keyPair.private.algorithm)
        assertTrue(keyPair.public.encoded.isNotEmpty())
    }

    @Test
    fun software_encrypt_decrypt_oaep_round_trip() {
        val keyPair = softwareRsa.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()
        val encryptedBytes = softwareRsa.encrypt(publicKey = keyPair.public, plainTextBytes = plainTextBytes)
        val decrypted = softwareRsa.decrypt(privateKey = keyPair.private, encryptedBytes = encryptedBytes)
        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun software_sign_verify_sha256_round_trip() {
        val keyPair = softwareRsa.generateKey()
        val plainTextBytes = "Passw0rd!".toByteArray()
        val signatureBytes = softwareRsa.sign(privateKey = keyPair.private, plainTextBytes = plainTextBytes)
        assertTrue(
            softwareRsa.verify(
                publicKey = keyPair.public,
                signatureBytes = signatureBytes,
                plainTextBytes = plainTextBytes,
            ),
        )
    }

    @Test
    fun keystore_generate_and_load_key_success() {
        val alias = "keystore_alias_rsa_${System.currentTimeMillis()}"
        keyStoreRsa.deleteKey(alias)
        keyStoreRsa.generateKey(keyStoreAlias = alias)

        assertTrue(keyStoreRsa.isKeyExist(alias))
        assertNotNull(keyStoreRsa.getPrivateKey(alias))
        assertNotNull(keyStoreRsa.getPublicKey(alias))
    }

    @Test
    fun keystore_encrypt_decrypt_oaep_round_trip() {
        val alias = "keystore_alias_rsa_encrypt_${System.currentTimeMillis()}"
        keyStoreRsa.deleteKey(alias)
        val keyPair = keyStoreRsa.generateKey(keyStoreAlias = alias)
        val plainTextBytes = "Passw0rd!".toByteArray()

        val encryptedBytes = keyStoreRsa.encrypt(
            publicKey = keyPair.public,
            plainTextBytes = plainTextBytes,
        )
        val decrypted = keyStoreRsa.decrypt(
            privateKey = keyPair.private,
            encryptedBytes = encryptedBytes,
        )
        assertArrayEquals(plainTextBytes, decrypted)
    }

    @Test
    fun keystore_sign_verify_pss_round_trip() {
        val alias = "keystore_alias_rsa_sign_${System.currentTimeMillis()}"
        keyStoreRsa.deleteKey(alias)
        val keyPair = keyStoreRsa.generateKey(keyStoreAlias = alias)
        val plainTextBytes = "Passw0rd!".toByteArray()

        val signatureBytes = keyStoreRsa.sign(
            privateKey = keyPair.private,
            plainTextBytes = plainTextBytes,
        )
        assertTrue(
            keyStoreRsa.verify(
                publicKey = keyPair.public,
                signatureBytes = signatureBytes,
                plainTextBytes = plainTextBytes,
            ),
        )
    }

    @Test
    fun keystore_verify_tampered_signature_returns_false() {
        val alias = "keystore_alias_rsa_tamper_${System.currentTimeMillis()}"
        keyStoreRsa.deleteKey(alias)
        val keyPair = keyStoreRsa.generateKey(keyStoreAlias = alias)
        val plainTextBytes = "Passw0rd!".toByteArray()
        val signatureBytes = keyStoreRsa.sign(privateKey = keyPair.private, plainTextBytes = plainTextBytes)
        val tampered = signatureBytes.copyOf().also { it[0] = (it[0] + 1).toByte() }

        assertFalse(
            keyStoreRsa.verify(
                publicKey = keyPair.public,
                signatureBytes = tampered,
                plainTextBytes = plainTextBytes,
            ),
        )
    }

    @Test
    fun get_key_returns_null_when_missing() {
        assertNull(keyStoreRsa.getPrivateKey("missing_rsa_${System.currentTimeMillis()}"))
        assertNull(keyStoreRsa.getPublicKey("missing_rsa_${System.currentTimeMillis()}"))
    }

    @Test
    fun generate_key_with_blank_alias_throws_invalid_key_alias() {
        try {
            keyStoreRsa.generateKey(keyStoreAlias = "  ")
            fail("Expected CryptoVaultException")
        } catch (e: CryptoVaultException) {
            assertEquals("INVALID_KEY_ALIAS", e.code)
        }
    }

    @Test
    fun is_support_strong_box_does_not_crash_on_api_28_plus() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return

        val context = InstrumentationRegistry.getInstrumentation().targetContext
        keyStoreRsa.isSupportStrongBox(context)
    }
}
