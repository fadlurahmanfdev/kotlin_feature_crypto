package com.fadlurahmanfdev.crypto_vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultCustomKeyVault
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESBlockMode
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESEncryptionPadding
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.spec.GCMParameterSpec

@RunWith(AndroidJUnit4::class)
class CryptoVaultCustomKeyVaultTest {

    private lateinit var customKeyVault: CryptoVaultCustomKeyVault
    private val plainText = "CustomSymmetricPlainText"

    @Before
    fun setUp() {
        customKeyVault = CryptoVaultCustomKeyVault()
    }

    @Test
    fun generateKey_returns_non_empty_encoded_key() {
        val key = customKeyVault.generateKey(CryptoVaultAlgorithm.AES)
        assertTrue(key.isNotEmpty())
    }

    @Test
    fun encrypt_and_decrypt_with_custom_transformation_and_iv() {
        val transformation = "${CryptoVaultAlgorithm.AES}/${CryptoVaultAESBlockMode.GCM}/${CryptoVaultAESEncryptionPadding.NoPadding}"
        val encodedKey = customKeyVault.generateKey(CryptoVaultAlgorithm.AES)
        val ivBytes = ByteArray(12)
        java.security.SecureRandom().nextBytes(ivBytes)
        val gcmSpec = GCMParameterSpec(128, ivBytes)

        val encrypted = customKeyVault.encrypt(
            algorithm = CryptoVaultAlgorithm.AES,
            encodedSecretKey = encodedKey,
            transformation = transformation,
            plainText = plainText,
            algorithmParameterSpec = gcmSpec,
        )
        assertTrue(encrypted.isNotEmpty())

        val decrypted = customKeyVault.decrypt(
            algorithm = CryptoVaultAlgorithm.AES,
            encodedSecretKey = encodedKey,
            transformation = transformation,
            algorithmParameterSpec = gcmSpec,
            encryptedText = encrypted,
        )
        assertEquals(plainText, decrypted)
    }

    @Test
    fun encrypt_with_generated_iv_and_decrypt() {
        val transformation = "${CryptoVaultAlgorithm.AES}/${CryptoVaultAESBlockMode.GCM}/${CryptoVaultAESEncryptionPadding.NoPadding}"
        val encodedKey = customKeyVault.generateKey(CryptoVaultAlgorithm.AES)

        val encryptedModel = customKeyVault.encrypt(
            algorithm = CryptoVaultAlgorithm.AES,
            encodedSecretKey = encodedKey,
            transformation = transformation,
            plainText = plainText,
        )
        assertTrue(encryptedModel.encryptedText.isNotEmpty())
        assertTrue(encryptedModel.ivKey.isNotEmpty())

        val decrypted = customKeyVault.decrypt(
            algorithm = CryptoVaultAlgorithm.AES,
            encodedSecretKey = encodedKey,
            transformation = transformation,
            algorithmParameterSpec = GCMParameterSpec(128, customKeyVault.decode(encryptedModel.ivKey)),
            encryptedText = encryptedModel.encryptedText,
        )
        assertEquals(plainText, decrypted)
    }
}
