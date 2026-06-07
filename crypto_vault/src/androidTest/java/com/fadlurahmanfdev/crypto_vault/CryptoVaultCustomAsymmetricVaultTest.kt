package com.fadlurahmanfdev.crypto_vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultCustomAsymmetricVault
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultBlockMode
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultPadding
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultSignatureAlgorithm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultCustomAsymmetricVaultTest {

    private lateinit var customAsymmetricVault: CryptoVaultCustomAsymmetricVault
    private val plainText = "CustomAsymmetricPlainText"

    @Before
    fun setUp() {
        customAsymmetricVault = CryptoVaultCustomAsymmetricVault()
    }

    @Test
    fun generateKey_returns_encoded_key_pair() {
        val key = customAsymmetricVault.generateKey(CryptoVaultAlgorithm.RSA, 2048)
        assertTrue(key.privateKey.isNotEmpty())
        assertTrue(key.publicKey.isNotEmpty())
    }

    @Test
    fun generate_and_verify_signature() {
        val key = customAsymmetricVault.generateKey(CryptoVaultAlgorithm.RSA, 2048)
        val signature = customAsymmetricVault.generateSignature(
            encodedPrivateKey = key.privateKey,
            plainText = plainText,
            algorithm = CryptoVaultAlgorithm.RSA,
            signatureAlgorithm = CryptoVaultSignatureAlgorithm.SHA256withRSA,
        )
        assertTrue(signature.isNotEmpty())
        assertTrue(
            customAsymmetricVault.verifySignature(
                encodedPublicKey = key.publicKey,
                signature = signature,
                plainText = plainText,
                algorithm = CryptoVaultAlgorithm.RSA,
                signatureAlgorithm = CryptoVaultSignatureAlgorithm.SHA256withRSA,
            )
        )
    }

    @Test
    fun verifySignature_returns_false_for_invalid_signature() {
        val key = customAsymmetricVault.generateKey(CryptoVaultAlgorithm.RSA, 2048)
        val invalidSignature = customAsymmetricVault.encode(ByteArray(128))
        assertFalse(
            customAsymmetricVault.verifySignature(
                encodedPublicKey = key.publicKey,
                signature = invalidSignature,
                plainText = plainText,
                algorithm = CryptoVaultAlgorithm.RSA,
                signatureAlgorithm = CryptoVaultSignatureAlgorithm.SHA256withRSA,
            )
        )
    }

    @Test
    fun encrypt_and_decrypt_with_block_mode_and_padding() {
        val key = customAsymmetricVault.generateKey(CryptoVaultAlgorithm.RSA, 2048)
        val encrypted = customAsymmetricVault.encrypt(
            algorithm = CryptoVaultAlgorithm.RSA,
            blockMode = CryptoVaultBlockMode.ECB,
            padding = CryptoVaultPadding.OAEPWithSHAAndMGF1Padding,
            encodedPublicKey = key.publicKey,
            plainText = plainText,
        )
        assertTrue(encrypted.isNotEmpty())

        val decrypted = customAsymmetricVault.decrypt(
            algorithm = CryptoVaultAlgorithm.RSA,
            blockMode = CryptoVaultBlockMode.ECB,
            padding = CryptoVaultPadding.OAEPWithSHAAndMGF1Padding,
            encodedPrivateKey = key.privateKey,
            encryptedText = encrypted,
        )
        assertEquals(plainText, decrypted)
    }
}
