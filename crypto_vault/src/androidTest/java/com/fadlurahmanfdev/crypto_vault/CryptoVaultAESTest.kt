package com.fadlurahmanfdev.crypto_vault

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESEncryptionPadding
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.spec.GCMParameterSpec


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
            blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
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
            blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
            encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
        )
        val encrypted = cryptoVaultAES.encrypt(
            secretKey = key,
            blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
            padding = CryptoVaultAESEncryptionPadding.NoPadding,
            plainText = "Passw0rd!"
        )
        assertEquals(true, encrypted.encryptedText.isNotEmpty())
        assertEquals(true, encrypted.ivKey.isNotEmpty())
        val decrypted = cryptoVaultAES.decrypt(
            secretKey = key,
            blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
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
            blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
            padding = CryptoVaultAESEncryptionPadding.NoPadding,
            plainText = "Passw0rd!"
        )
        assertEquals(true, encrypted.encryptedText.isNotEmpty())
        assertEquals(true, encrypted.ivKey.isNotEmpty())
        val decrypted = cryptoVaultAES.decrypt(
            encodedSecretKey = key,
            blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
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
                blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
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
                blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
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
}