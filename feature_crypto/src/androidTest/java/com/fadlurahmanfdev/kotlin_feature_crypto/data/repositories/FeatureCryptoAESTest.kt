package com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.kotlin_feature_crypto.FeatureCryptoAES
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith


@RunWith(AndroidJUnit4::class)
class FeatureCryptoAESTest {
    private lateinit var cryptoAESRepository: CryptoAESRepository

    @Before
    fun setUp() {
        cryptoAESRepository = FeatureCryptoAES()
    }

    @Test
    fun generate_secure_key_success_is_not_empty() {
        val key = cryptoAESRepository.generateKey()
        assertEquals(true, key.isNotEmpty())
    }

    @Test
    fun generate_key_success_is_not_empty() {
        val key = cryptoAESRepository.generateKey()
        assertEquals(true, key.isNotEmpty())
    }

    @Test
    fun generate_iv_key_success_is_not_empty() {
        val ivKey = cryptoAESRepository.generateIVKey()
        assertEquals(true, ivKey.isNotEmpty())
    }

    @Test
    fun encrypt_decrypt_aes_success_default_method() {
        val plainText = "Plain Text AES"
        val key = cryptoAESRepository.generateKey()
        val ivKey = cryptoAESRepository.generateIVKey()
        val encrypted = try {
            cryptoAESRepository.encrypt(
                key = key,
                ivKey = ivKey,
                plainText = plainText
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, encrypted != null)
        val decrypted = cryptoAESRepository.decrypt(
            key = key,
            ivKey = ivKey,
            encryptedText = encrypted!!
        )
        assertEquals(plainText, decrypted)
    }

    @Test
    fun encrypt_decrypt_aes_failed_using_fake_key() {
        val plainText = "Plain Text AES"
        val key = "fake_key"
        val ivKey = cryptoAESRepository.generateIVKey()
        val encrypted = try {
            cryptoAESRepository.encrypt(
                key = key,
                ivKey = ivKey,
                plainText = plainText
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, encrypted == null)
    }

    @Test
    fun encrypt_decrypt_aes_failed_using_fake_iv_key() {
        val plainText = "Plain Text AES"
        val key = cryptoAESRepository.generateKey()
        val ivKey = "fake_iv_key"
        val encrypted = try {
            cryptoAESRepository.encrypt(
                key = key,
                ivKey = ivKey,
                plainText = plainText
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, encrypted == null)
    }
}