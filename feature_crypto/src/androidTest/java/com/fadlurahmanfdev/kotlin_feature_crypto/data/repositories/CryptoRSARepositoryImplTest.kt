package com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.data.impl_repositories.CryptoRSARepositoryImpl
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
        val signature = try {
            cryptoRSARepository.generateSignature(
                encodedPrivateKey = key.privateKey,
                plainText = plainSignatureText,
                signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA256withRSA
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, signature != null)
        assertEquals(true, (signature ?: "").isNotEmpty())
        val isVerify = cryptoRSARepository.verifySignature(
            encodedPublicKey = key.publicKey,
            signature = signature!!,
            plainText = plainSignatureText,
            signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA256withRSA
        )
        assertEquals(true, isVerify)
    }

    @Test
    fun generate_and_verify_signature_with_sha1_rsa() {
        val plainSignatureText = "Plain Signature Text"
        val key = cryptoRSARepository.generateKey()
        val signature = try {
            cryptoRSARepository.generateSignature(
                encodedPrivateKey = key.privateKey,
                plainText = plainSignatureText,
                signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA1withRSA,
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, signature != null)
        assertEquals(true, (signature ?: "").isNotEmpty())
        val isVerify = cryptoRSARepository.verifySignature(
            encodedPublicKey = key.publicKey,
            signature = signature!!,
            plainText = plainSignatureText,
            signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA1withRSA
        )
        assertEquals(true, isVerify)
    }

    @Test
    fun failed_generate_signature_with_non_private_key() {
        val plainSignatureText = "Plain Signature Text"
        val key = cryptoRSARepository.generateKey()
        val signature = try {
            cryptoRSARepository.generateSignature(
                encodedPrivateKey = key.publicKey,
                plainText = plainSignatureText,
                signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA1withRSA
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, signature == null)
    }

    @Test
    fun failed_encrypt_with_non_public_key() {
        val plainText = "Plain Text RSA"
        val key = cryptoRSARepository.generateKey()
        val encrypted = try {
            cryptoRSARepository.encrypt(
                encodedPublicKey = key.privateKey,
                plainText = plainText,
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, encrypted == null)
    }

    @Test
    fun failed_decrypt_rsa_with_non_private_key() {
        val plainText = "Plain Text RSA"
        val key = cryptoRSARepository.generateKey()
        val encrypted = try {
            cryptoRSARepository.encrypt(
                encodedPublicKey = key.publicKey,
                plainText = plainText,
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, encrypted != null)
        val decrypted = try {
            cryptoRSARepository.decrypt(
                encodedPrivateKey = key.publicKey,
                encryptedText = encrypted!!,
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, decrypted == null)
    }
}