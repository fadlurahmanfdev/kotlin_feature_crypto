package com.fadlurahmanfdev.crypto_vault

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.os.Build
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESBlockMode
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESEncryptionPadding
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec


@RunWith(AndroidJUnit4::class)
class CryptoVaultAESTest {
    private lateinit var cryptoVaultAES: CryptoVaultAES

    @Before
    fun setUp() {
        cryptoVaultAES = CryptoVaultAES()
    }

    @Test
    fun generate_secret_key_non_android_keystore_success() {
        val key = cryptoVaultAES.generateKey()
        assertEquals(true, key.isNotEmpty())
    }

    @Test
    fun generate_secret_key_via_android_keystore_success() {
        val keystoreAlias = "example_keystore_aes"
        val key = cryptoVaultAES.generateKeyFromAndroidKeyStore(
            keystoreAlias = keystoreAlias,
            strongBoxBacked = false,
            blockMode = CryptoVaultAESBlockMode.GCM,
            encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
        )
        assertEquals("AES", key.algorithm)
    }

    @Test
    fun generate_iv_key_success_is_not_empty() {
        val ivKey = cryptoVaultAES.generateIVParameterSpecKey()
        assertEquals(true, ivKey.isNotEmpty())
    }

    @Test
    fun generate_iv_gcm_key_success_is_not_empty() {
        val ivKey = cryptoVaultAES.generateIVGCMParameterSpecKey()
        assertEquals(true, ivKey.isNotEmpty())
    }

    @Test
    fun encrypt_decrypt_aes_via_android_keystore_success() {
        val aesAliasForTest = "aes_alias_for_test"
        cryptoVaultAES.deleteKey(aesAliasForTest)
        val key = cryptoVaultAES.generateKeyFromAndroidKeyStore(
            keystoreAlias = aesAliasForTest,
            strongBoxBacked = false,
            blockMode = CryptoVaultAESBlockMode.GCM,
            encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
        )
        val encrypted = cryptoVaultAES.encrypt(
            secretKey = key,
            blockMode = CryptoVaultAESBlockMode.GCM,
            padding = CryptoVaultAESEncryptionPadding.NoPadding,
            plainText = "Passw0rd!"
        )
        assertEquals(true, encrypted.encryptedText.isNotEmpty())
        assertEquals(true, encrypted.ivKey.isNotEmpty())
        val decrypted = cryptoVaultAES.decrypt(
            secretKey = key,
            blockMode = CryptoVaultAESBlockMode.GCM,
            padding = CryptoVaultAESEncryptionPadding.NoPadding,
            algorithmParameterSpec = GCMParameterSpec(
                128,
                cryptoVaultAES.decode(encrypted.ivKey)
            ),
            encryptedText = encrypted.encryptedText
        )
        assertEquals("Passw0rd!", decrypted)
    }

    @Test
    fun encrypt_decrypt_aes_non_android_keystore_success() {
        val key = cryptoVaultAES.generateKey()
        val encrypted = cryptoVaultAES.encrypt(
            encodedSecretKey = key,
            blockMode = CryptoVaultAESBlockMode.GCM,
            padding = CryptoVaultAESEncryptionPadding.NoPadding,
            plainText = "Passw0rd!"
        )
        assertEquals(true, encrypted.encryptedText.isNotEmpty())
        assertEquals(true, encrypted.ivKey.isNotEmpty())
        val decrypted = cryptoVaultAES.decrypt(
            encodedSecretKey = key,
            blockMode = CryptoVaultAESBlockMode.GCM,
            padding = CryptoVaultAESEncryptionPadding.NoPadding,
            algorithmParameterSpec = GCMParameterSpec(
                128,
                cryptoVaultAES.decode(encrypted.ivKey)
            ),
            encryptedText = encrypted.encryptedText
        )
        assertEquals("Passw0rd!", decrypted)
    }

    @Test
    fun encrypt_decrypt_aes_failed_using_fake_secret_key() {
        // base64 encode from "fake_encoded_secret_key"
        val fakeEncodedSecretKey = "ZmFrZV9lbmNvZGVkX3NlY3JldF9rZXk="
        val encrypted = try {
            cryptoVaultAES.encrypt(
                encodedSecretKey = fakeEncodedSecretKey,
                blockMode = CryptoVaultAESBlockMode.GCM,
                padding = CryptoVaultAESEncryptionPadding.NoPadding,
                plainText = "Passw0rd!"
            )
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed - ${e.message}", e)
            null
        }
        assertEquals(true, encrypted == null)
    }

    @Test
    fun encrypt_decrypt_aes_failed_using_fake_iv_key() {
        // base64 encode from "fake_encoded_secret_key"
        val fakeEncodedSecretKey = "ZmFrZV9lbmNvZGVkX3NlY3JldF9rZXk="
        val fakeEncodedIVKey = "ZmFrZV9lbmNvZGVkX2l2X2tleQ=="
        val encrypted = try {
            cryptoVaultAES.encrypt(
                encodedSecretKey = fakeEncodedSecretKey,
                blockMode = CryptoVaultAESBlockMode.GCM,
                padding = CryptoVaultAESEncryptionPadding.NoPadding,
                algorithmParameterSpec = GCMParameterSpec(
                    128,
                    cryptoVaultAES.decode(fakeEncodedIVKey)
                ),
                plainText = "Passw0rd!"
            )
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed - ${e.message}", e)
            null
        }
        assertEquals(true, encrypted == null)
    }

    @Test
    fun encrypt_decrypt_aes_cbc_pkcs5_with_custom_iv_success() {
        val key = cryptoVaultAES.generateKey()
        val ivKey = cryptoVaultAES.generateIVParameterSpecKey()
        val encrypted = cryptoVaultAES.encrypt(
            encodedSecretKey = key,
            blockMode = CryptoVaultAESBlockMode.CBC,
            padding = CryptoVaultAESEncryptionPadding.PKCS5Padding,
            algorithmParameterSpec = IvParameterSpec(cryptoVaultAES.decode(ivKey)),
            plainText = "Passw0rd!",
        )
        val decrypted = cryptoVaultAES.decrypt(
            encodedSecretKey = key,
            blockMode = CryptoVaultAESBlockMode.CBC,
            padding = CryptoVaultAESEncryptionPadding.PKCS5Padding,
            algorithmParameterSpec = IvParameterSpec(cryptoVaultAES.decode(ivKey)),
            encryptedText = encrypted,
        )
        assertEquals("Passw0rd!", decrypted)
    }

    @Test
    fun encrypt_with_secret_key_and_custom_iv_success() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return

        val alias = "aes_custom_iv_test_${System.currentTimeMillis()}"
        cryptoVaultAES.deleteKey(alias)
        val secretKey = cryptoVaultAES.generateKeyFromAndroidKeyStore(
            keystoreAlias = alias,
            strongBoxBacked = false,
            blockMode = CryptoVaultAESBlockMode.GCM,
            encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
            randomizedEncryptionRequired = false,
        )
        val ivKey = cryptoVaultAES.generateIVGCMParameterSpecKey()
        val encrypted = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            blockMode = CryptoVaultAESBlockMode.GCM,
            padding = CryptoVaultAESEncryptionPadding.NoPadding,
            algorithmParameterSpec = GCMParameterSpec(128, cryptoVaultAES.decode(ivKey)),
            plainText = "Passw0rd!",
        )
        val decrypted = cryptoVaultAES.decrypt(
            secretKey = secretKey,
            blockMode = CryptoVaultAESBlockMode.GCM,
            padding = CryptoVaultAESEncryptionPadding.NoPadding,
            algorithmParameterSpec = GCMParameterSpec(128, cryptoVaultAES.decode(ivKey)),
            encryptedText = encrypted,
        )
        assertEquals("Passw0rd!", decrypted)
    }

    @Test
    fun get_key_from_android_keystore_returns_null_when_missing() {
        val missingAlias = "missing_aes_alias_${System.currentTimeMillis()}"
        assertNull(cryptoVaultAES.getKeyFromAndroidKeyStore(missingAlias))
    }

    @Test
    fun get_key_from_android_keystore_returns_key_when_present() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return

        val alias = "aes_get_key_test_${System.currentTimeMillis()}"
        cryptoVaultAES.deleteKey(alias)
        cryptoVaultAES.generateKeyFromAndroidKeyStore(
            keystoreAlias = alias,
            strongBoxBacked = false,
            blockMode = CryptoVaultAESBlockMode.GCM,
            encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
        )
        assertNotNull(cryptoVaultAES.getKeyFromAndroidKeyStore(alias))
    }
}