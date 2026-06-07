package com.fadlurahmanfdev.crypto_vault

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultEC
import com.fadlurahmanfdev.crypto_vault.enum.ec.CryptoVaultECSignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.ec.CryptoVaultECTransformation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultECTest {

    private lateinit var cryptoVaultEC: CryptoVaultEC
    private val plainText = "Passw0rd!"

    @Before
    fun setUp() {
        cryptoVaultEC = CryptoVaultEC()
    }

    @Test
    fun generate_key_non_android_keystore_success() {
        val key = cryptoVaultEC.generateKey()
        assertTrue(key.publicKey.isNotEmpty())
        assertTrue(key.privateKey.isNotEmpty())
    }

    @Test
    fun generate_and_verify_signature_non_android_keystore() {
        val key = cryptoVaultEC.generateKey()
        val signature = cryptoVaultEC.generateSignature(
            encodedPrivateKey = key.privateKey,
            plainText = plainText,
            signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
        )
        assertTrue(signature.isNotEmpty())
        assertTrue(
            cryptoVaultEC.verifySignature(
                encodedPublicKey = key.publicKey,
                signature = signature,
                plainText = plainText,
                signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
            )
        )
    }

    @Test
    fun encrypt_and_decrypt_non_android_keystore() {
        val key = cryptoVaultEC.generateKey()
        val transformation = CryptoVaultECTransformation.ECDH_AES_GCM
        val encrypted = cryptoVaultEC.encrypt(
            encodedPublicKey = key.publicKey,
            transformation = transformation,
            plainText = plainText,
        )
        assertTrue(encrypted.isNotEmpty())
        val decrypted = cryptoVaultEC.decrypt(
            encodedPrivateKey = key.privateKey,
            transformation = transformation,
            encryptedText = encrypted,
        )
        assertEquals(plainText, decrypted)
    }

    @Test
    fun verify_signature_returns_false_for_invalid_signature() {
        val key = cryptoVaultEC.generateKey()
        val invalidSignature = cryptoVaultEC.encode(ByteArray(64))
        assertFalse(
            cryptoVaultEC.verifySignature(
                encodedPublicKey = key.publicKey,
                signature = invalidSignature,
                plainText = plainText,
                signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
            )
        )
    }

    @Test
    fun generate_shared_secret_and_derive_aes_key() {
        val bobKey = cryptoVaultEC.generateKey()
        val aliceKey = cryptoVaultEC.generateKey()

        val bobSharedSecret = cryptoVaultEC.generateSharedSecret(
            ourEncodedPrivateKey = bobKey.privateKey,
            otherEncodedPublicKey = aliceKey.publicKey,
        )
        val aliceSharedSecret = cryptoVaultEC.generateSharedSecret(
            ourEncodedPrivateKey = aliceKey.privateKey,
            otherEncodedPublicKey = bobKey.publicKey,
        )

        assertTrue(bobSharedSecret.isNotEmpty())
        assertTrue(aliceSharedSecret.isNotEmpty())

        val bobDerivedKey = cryptoVaultEC.derivedSharedSecret(bobSharedSecret)
        val aliceDerivedKey = cryptoVaultEC.derivedSharedSecret(aliceSharedSecret)
        assertTrue(bobDerivedKey.isNotEmpty())
        assertTrue(aliceDerivedKey.isNotEmpty())
    }

    @Test
    fun generate_key_via_android_keystore_and_sign_verify() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return

        val keystoreAlias = "ec_keystore_test_${System.currentTimeMillis()}"
        cryptoVaultEC.deleteKey(keystoreAlias)

        val keyPair = cryptoVaultEC.generateKeyFromAndroidKeyStore(
            keystoreAlias = keystoreAlias,
            strongBoxBacked = false,
        )
        assertNotNull(keyPair.private)
        assertNotNull(keyPair.public)

        val signature = cryptoVaultEC.generateSignature(
            privateKey = keyPair.private,
            plainText = plainText,
            signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
        )
        assertTrue(signature.isNotEmpty())

        val publicKey = cryptoVaultEC.getPublicAndroidKeyStore(keystoreAlias)
        assertNotNull(publicKey)
        assertTrue(
            cryptoVaultEC.verifySignature(
                publicKey = publicKey!!,
                signature = signature,
                plainText = plainText,
                signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
            )
        )
    }

    @Test
    fun get_private_key_from_android_keystore() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return

        val keystoreAlias = "ec_private_key_test_${System.currentTimeMillis()}"
        cryptoVaultEC.deleteKey(keystoreAlias)
        cryptoVaultEC.generateKeyFromAndroidKeyStore(
            keystoreAlias = keystoreAlias,
            strongBoxBacked = false,
        )

        assertNotNull(cryptoVaultEC.getPrivateKeyAndroidKeyStore(keystoreAlias))
        assertNotNull(cryptoVaultEC.getPublicAndroidKeyStore(keystoreAlias))
    }
}
