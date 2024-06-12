package com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith


@RunWith(AndroidJUnit4::class)
class CryptoAESRepositoryImplTest {
    lateinit var cryptoAESRepository: CryptoAESRepository

    @Before
    fun setUp() {
        cryptoAESRepository = CryptoAESRepositoryImpl()
    }

    @Test
    fun generate_key_success_is_not_empty() {
        val key = cryptoAESRepository.generateKey()
        assertEquals(true, key.isNotEmpty())
    }

    @Test
    fun encrypt_decrypt_aes_success_method_aes_gcm_no_padding() {
        val plainText = "Plain Text AES"
        val key = cryptoAESRepository.generateKey()
        val ivKey = cryptoAESRepository.generateIVKey()
        val encrypted = cryptoAESRepository.encrypt(
            encodedKey = key,
            encodedIVKey = ivKey,
            plainText = plainText,
            method = AESMethod.AES_GCM_NoPadding
        )
        assertEquals(true, encrypted != null)
        val decrypted = cryptoAESRepository.decrypt(
            encodedKey = key,
            encodedIVKey = ivKey,
            encryptedText = encrypted!!,
            method = AESMethod.AES_GCM_NoPadding
        )
        assertEquals(plainText, decrypted)
    }

    @Test
    fun encrypt_decrypt_aes_success_method_aes_cbc_iso10126_padding() {
        val plainText = "Plain Text Iso 10126"
        val key = cryptoAESRepository.generateKey()
        val ivKey = cryptoAESRepository.generateIVKey()
        val encrypted = cryptoAESRepository.encrypt(
            encodedKey = key,
            encodedIVKey = ivKey,
            plainText = plainText,
            method = AESMethod.AES_CBC_ISO10126Padding
        )
        assertEquals(true, encrypted != null)
        val decrypted = cryptoAESRepository.decrypt(
            encodedKey = key,
            encodedIVKey = ivKey,
            encryptedText = encrypted!!,
            method = AESMethod.AES_CBC_ISO10126Padding
        )
        assertEquals(plainText, decrypted)
    }

    @Test
    fun failed_decrypt_with_different_method() {
        val plainText = "Plain Text AES"
        val key = cryptoAESRepository.generateKey()
        val ivKey = cryptoAESRepository.generateIVKey()
        val encrypted = cryptoAESRepository.encrypt(
            encodedKey = key,
            encodedIVKey = ivKey,
            plainText = plainText,
            method = AESMethod.AES_GCM_NoPadding
        )
        assertEquals(true, encrypted != null)
        val decrypted = cryptoAESRepository.decrypt(
            encodedKey = key,
            encodedIVKey = ivKey,
            encryptedText = encrypted!!,
            method = AESMethod.AES_CBC_ISO10126Padding
        )
        assertEquals(true, decrypted == null)
    }

    @Test
    fun failed_encrypt_with_fake_aes_key() {
        val plainText = "Plain Text AES"
        val ivKey = cryptoAESRepository.generateIVKey()
        val encrypted = cryptoAESRepository.encrypt(
            encodedKey = "SOME FAKE AES KEY",
            encodedIVKey = ivKey,
            plainText = plainText,
            method = AESMethod.AES_GCM_NoPadding
        )
        assertEquals(true, encrypted == null)
    }

    @Test
    fun failed_decrypt_with_fake_aes_key() {
        val key = cryptoAESRepository.generateKey()
        val ivKey = cryptoAESRepository.generateIVKey()
        val decrypted = cryptoAESRepository.decrypt(
            encodedKey = key,
            encodedIVKey = ivKey,
            encryptedText = "Fake Encrypted Text",
            method = AESMethod.AES_GCM_NoPadding
        )
        assertEquals(true, decrypted == null)
    }

    @Test
    fun failed_encrypt_with_fake_iv_key() {
        val key = cryptoAESRepository.generateKey()
        val encrypted = cryptoAESRepository.encrypt(
            encodedKey = key,
            encodedIVKey = "FAKE IV KEY",
            method = AESMethod.AES_GCM_NoPadding,
            plainText = "Passw0rd!"
        )
        assertEquals(true, encrypted == null)
    }

    @Test
    fun failed_decrypt_with_fake_iv_key() {
        val key = cryptoAESRepository.generateKey()
        val ivKey = cryptoAESRepository.generateIVKey()
        val encrypted = cryptoAESRepository.encrypt(
            encodedKey = key,
            encodedIVKey = ivKey,
            method = AESMethod.AES_GCM_NoPadding,
            plainText = "Passw0rd!"
        )
        assertEquals(true, encrypted != null)
        val decrypted = cryptoAESRepository.decrypt(
            encodedKey = key,
            encodedIVKey = "FAKE IV KEY",
            encryptedText = encrypted!!,
            method = AESMethod.AES_GCM_NoPadding
        )
        assertEquals(true, decrypted == null)
    }
}