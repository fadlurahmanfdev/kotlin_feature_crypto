package co.id.fadlurahmanf.kotlin_core_crypto.repositories

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.enums.AESMethod
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoAESRepository
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoAESRepositoryImpl
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
    fun generate_key_is_not_empty() {
        val key = cryptoAESRepository.generateKey()
        assertEquals(true, key.isNotEmpty())
    }

    @Test
    fun encrypt_decrypt_aes_success() {
        val plainText = "Plain Text AES"
        val key = cryptoAESRepository.generateKey()
        val encrypted = cryptoAESRepository.encrypt(
            encodedKey = key,
            plainText = plainText,
            method = AESMethod.AES_GCM_NoPadding
        )
        assertEquals(true, encrypted != null)
        val decrypted = cryptoAESRepository.decrypt(
            encodedKey = key,
            encryptedText = encrypted!!,
            method = AESMethod.AES_GCM_NoPadding
        )
        assertEquals(plainText, decrypted)
    }

    @Test
    fun failed_encrypt_with_fake_aes_key() {
        val plainText = "Plain Text AES"
        val key = cryptoAESRepository.generateKey()
        val encrypted = cryptoAESRepository.encrypt(
            encodedKey = "SOME FAKE AES KEY",
            plainText = plainText,
            method = AESMethod.AES_GCM_NoPadding
        )
        assertEquals(true, encrypted == null)
    }
}