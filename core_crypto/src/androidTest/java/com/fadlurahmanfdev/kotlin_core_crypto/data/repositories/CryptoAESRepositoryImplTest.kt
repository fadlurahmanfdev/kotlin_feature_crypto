package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.kotlin_core_crypto.data.impl_repositories.CryptoAESRepositoryImpl
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith


@RunWith(AndroidJUnit4::class)
class CryptoAESRepositoryImplTest {
    private lateinit var cryptoAESRepository: CryptoAESRepository

    @Before
    fun setUp() {
        cryptoAESRepository = CryptoAESRepositoryImpl()
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
        var encrypted: String? = null
        try {
            encrypted = cryptoAESRepository.encrypt(
                key = key,
                ivKey = ivKey,
                plainText = plainText
            )
        } catch (e: Throwable) { }
        assertEquals(true, encrypted != null)
        val decrypted = cryptoAESRepository.decrypt(
            key = key,
            ivKey = ivKey,
            encryptedText = encrypted!!
        )
        assertEquals(plainText, decrypted)
    }
}