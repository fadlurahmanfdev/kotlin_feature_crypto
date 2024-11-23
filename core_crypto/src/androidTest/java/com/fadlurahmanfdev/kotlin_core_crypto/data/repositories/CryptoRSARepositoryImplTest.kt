package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSAMethod
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.RSASignatureMethod
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoRSARepositoryImplTest {
    private lateinit var cryptoRSARepository: CryptoRSARepository

    @Before
    fun setUp() {
        cryptoRSARepository = CryptoRSARepositoryImpl()
    }

    @Test
    fun generate_key_success_is_not_empty() {
        val key = cryptoRSARepository.generateKey()
        assertEquals(true, key.publicKey.isNotEmpty())
        assertEquals(true, key.privateKey.isNotEmpty())
    }

    @Test
    fun generate_and_verify_signature_with_sha256_rsa() {
        val plainSignatureText = "Plain Signature Text"
        val key = cryptoRSARepository.generateKey()
        val signature = cryptoRSARepository.generateSignature(
            encodedPrivateKey = key.privateKey,
            plainText = plainSignatureText,
            method = RSASignatureMethod.SHA256withRSA
        )
        assertEquals(true, signature != null)
        assertEquals(true, (signature ?: "").isNotEmpty())
        val isVerify = cryptoRSARepository.verifySignature(
            publicKey = key.publicKey,
            signature = signature!!,
            plainText = plainSignatureText,
            method = RSASignatureMethod.SHA256withRSA
        )
        assertEquals(true, isVerify)
    }

    @Test
    fun generate_and_verify_signature_with_sha1_rsa() {
        val plainSignatureText = "Plain Signature Text"
        val key = cryptoRSARepository.generateKey()
        val signature = cryptoRSARepository.generateSignature(
            encodedPrivateKey = key.privateKey,
            plainText = plainSignatureText,
            method = RSASignatureMethod.SHA1withRSA
        )
        assertEquals(true, signature != null)
        assertEquals(true, (signature ?: "").isNotEmpty())
        val isVerify = cryptoRSARepository.verifySignature(
            publicKey = key.publicKey,
            signature = signature!!,
            plainText = plainSignatureText,
            method = RSASignatureMethod.SHA1withRSA
        )
        assertEquals(true, isVerify)
    }

    @Test
    fun encrypt_decrypt_rsa_success_with_method_ecb_pkcs1_padding() {
        val plainText = "Plain Text RSA"
        val key = cryptoRSARepository.generateKey()
        val encrypted = cryptoRSARepository.encrypt(
            encodedPublicKey = key.publicKey,
            plainText = plainText,
            method = RSAMethod.RSA_ECB_PKCS1Padding
        )
        assertEquals(true, encrypted != null)
        val decrypted = cryptoRSARepository.decrypt(
            privateKey = key.privateKey,
            encryptedText = encrypted!!,
            method = RSAMethod.RSA_ECB_PKCS1Padding
        )
        assertEquals(true, decrypted != null)
        assertEquals(plainText, decrypted)
    }

    @Test
    fun encrypt_decrypt_rsa_success_with_method_ecb_OAEP_padding() {
        val plainText = "Plain Text RSA"
        val key = cryptoRSARepository.generateKey()
        val encrypted = cryptoRSARepository.encrypt(
            encodedPublicKey = key.publicKey,
            plainText = plainText,
            method = RSAMethod.RSA_ECB_OAEPPadding
        )
        assertEquals(true, encrypted != null)
        val decrypted = cryptoRSARepository.decrypt(
            privateKey = key.privateKey,
            encryptedText = encrypted!!,
            method = RSAMethod.RSA_ECB_OAEPPadding
        )
        assertEquals(true, decrypted != null)
        assertEquals(plainText, decrypted)
    }

    @Test
    fun failed_generate_signature_with_non_private_key() {
        val plainSignatureText = "Plain Signature Text"
        val key = cryptoRSARepository.generateKey()
        val signature = cryptoRSARepository.generateSignature(
            encodedPrivateKey = key.publicKey,
            plainText = plainSignatureText,
            method = RSASignatureMethod.SHA1withRSA
        )
        assertEquals(true, signature == null)
    }

    @Test
    fun failed_encrypt_with_non_public_key() {
        val plainText = "Plain Text RSA"
        val key = cryptoRSARepository.generateKey()
        val encrypted = cryptoRSARepository.encrypt(
            encodedPublicKey = key.privateKey,
            plainText = plainText,
            method = RSAMethod.RSA_ECB_PKCS1Padding
        )
        assertEquals(true, encrypted == null)
    }

    @Test
    fun failed_decrypt_rsa_with_non_private_key() {
        val plainText = "Plain Text RSA"
        val key = cryptoRSARepository.generateKey()
        val encrypted = cryptoRSARepository.encrypt(
            encodedPublicKey = key.publicKey,
            plainText = plainText,
            method = RSAMethod.RSA_ECB_PKCS1Padding
        )
        assertEquals(true, encrypted != null)
        val decrypted = cryptoRSARepository.decrypt(
            privateKey = key.publicKey,
            encryptedText = encrypted!!,
            method = RSAMethod.RSA_ECB_PKCS1Padding
        )
        assertEquals(true, decrypted == null)
    }
}