package com.fadlurahmanfdev.crypto_vault

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSA
import com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSAAndroidKeyStore
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException
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
        val plainText = "Passw0rd!".toByteArray()
        val encrypted = softwareRsa.encrypt(publicKey = keyPair.public, plainText = plainText)
        val decrypted = softwareRsa.decrypt(privateKey = keyPair.private, encrypted = encrypted)
        assertArrayEquals(plainText, decrypted)
    }

    @Test
    fun software_sign_verify_sha256_round_trip() {
        val keyPair = softwareRsa.generateKey()
        val plainText = "Passw0rd!".toByteArray()
        val signature = softwareRsa.sign(privateKey = keyPair.private, plainText = plainText)
        assertTrue(
            softwareRsa.verify(
                publicKey = keyPair.public,
                signature = signature,
                plainText = plainText,
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
        val plainText = "Passw0rd!".toByteArray()

        val encrypted = keyStoreRsa.encrypt(
            publicKey = keyPair.public,
            plainText = plainText,
        )
        val decrypted = keyStoreRsa.decrypt(
            privateKey = keyPair.private,
            encrypted = encrypted,
        )
        assertArrayEquals(plainText, decrypted)
    }

    @Test
    fun keystore_sign_verify_pss_round_trip() {
        val alias = "keystore_alias_rsa_sign_${System.currentTimeMillis()}"
        keyStoreRsa.deleteKey(alias)
        val keyPair = keyStoreRsa.generateKey(keyStoreAlias = alias)
        val plainText = "Passw0rd!".toByteArray()

        val signature = keyStoreRsa.sign(
            privateKey = keyPair.private,
            plainText = plainText,
        )
        assertTrue(
            keyStoreRsa.verify(
                publicKey = keyPair.public,
                signature = signature,
                plainText = plainText,
            ),
        )
    }

    @Test
    fun keystore_verify_tampered_signature_returns_false() {
        val alias = "keystore_alias_rsa_tamper_${System.currentTimeMillis()}"
        keyStoreRsa.deleteKey(alias)
        val keyPair = keyStoreRsa.generateKey(keyStoreAlias = alias)
        val plainText = "Passw0rd!".toByteArray()
        val signature = keyStoreRsa.sign(privateKey = keyPair.private, plainText = plainText)
        val tampered = signature.copyOf().also { it[0] = (it[0] + 1).toByte() }

        assertFalse(
            keyStoreRsa.verify(
                publicKey = keyPair.public,
                signature = tampered,
                plainText = plainText,
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
