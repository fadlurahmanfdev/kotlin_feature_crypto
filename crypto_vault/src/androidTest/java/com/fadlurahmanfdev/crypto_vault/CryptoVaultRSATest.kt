package com.fadlurahmanfdev.crypto_vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSAEncryptionPadding
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSASignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSASignaturePadding
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationPadding
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CryptoVaultRSATest {
    private lateinit var cryptoVaultRSA: CryptoVaultRSA

    @Before
    fun setUp() {
        cryptoVaultRSA = CryptoVaultRSA()
    }

    @Test
    fun generate_key_via_android_keystore() {
        val keystoreAlias = "keystore_alias_rsa_for_testing"
        cryptoVaultRSA.deleteKey(keystoreAlias)
        cryptoVaultRSA.generateKeyFromAndroidKeyStore(
            keystoreAlias = keystoreAlias,
            encryptionPaddings = arrayOf(
                CryptoVaultRSAEncryptionPadding.RSA_PKCS1
            ),
            signaturePaddings = arrayOf(
                CryptoVaultRSASignaturePadding.RSA_PKCS1
            )
        )
        assertEquals(true, true)
    }

    @Test
    fun generate_key_non_android_keystore() {
        val key = cryptoVaultRSA.generateKey()
        assertEquals(true, key.publicKey.isNotEmpty())
        assertEquals(true, key.privateKey.isNotEmpty())
    }

    @Test
    fun generate_and_verify_signature_using_key_from_android_keystore() {
        val keystoreAlias = "keystore_alias_rsa_for_testing"
        val plainSignatureText = "Plain Signature Text"
        cryptoVaultRSA.deleteKey(keystoreAlias)
        cryptoVaultRSA.generateKeyFromAndroidKeyStore(
            keystoreAlias = keystoreAlias,
            encryptionPaddings = arrayOf(
                CryptoVaultRSAEncryptionPadding.RSA_PKCS1
            ),
            signaturePaddings = arrayOf(
                CryptoVaultRSASignaturePadding.RSA_PKCS1
            )
        )

        val privateKey = cryptoVaultRSA.getPrivateKeyAndroidKeyStore(keystoreAlias = keystoreAlias)
        assertEquals(true, privateKey != null)

        val signature = try {
            cryptoVaultRSA.generateSignature(
                privateKey = privateKey!!,
                plainText = plainSignatureText,
                signatureAlgorithm = CryptoVaultRSASignatureAlgorithm.MD5withRSA
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, signature != null)
        assertEquals(true, (signature ?: "").isNotEmpty())

        val publicKey = cryptoVaultRSA.getPublicAndroidKeyStore(keystoreAlias = keystoreAlias)
        assertEquals(true, publicKey != null)
        val isVerify = cryptoVaultRSA.verifySignature(
            publicKey = publicKey!!,
            signature = signature!!,
            plainText = plainSignatureText,
            signatureAlgorithm = CryptoVaultRSASignatureAlgorithm.MD5withRSA,
        )
        assertEquals(true, isVerify)
    }

    @Test
    fun generate_and_verify_signature_using_non_android_keystore() {
        val plainSignatureText = "Plain Signature Text"
        val key = cryptoVaultRSA.generateKey()
        val signature = try {
            cryptoVaultRSA.generateSignature(
                encodedPrivateKey = key.privateKey,
                plainText = plainSignatureText,
                signatureAlgorithm = CryptoVaultRSASignatureAlgorithm.MD5withRSA
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, signature != null)
        assertEquals(true, (signature ?: "").isNotEmpty())

        val isVerify = cryptoVaultRSA.verifySignature(
            encodedPublicKey = key.publicKey,
            signature = signature!!,
            plainText = plainSignatureText,
            signatureAlgorithm = CryptoVaultRSASignatureAlgorithm.MD5withRSA,
        )
        assertEquals(true, isVerify)
    }

    @Test
    fun encrypt_decrypt_via_android_keystore() {
        val keystoreAlias = "keystore_alias_rsa_for_testing"
        val plainText = "Plain RSA Text"
        cryptoVaultRSA.deleteKey(keystoreAlias)
        val key = cryptoVaultRSA.generateKeyFromAndroidKeyStore(
            keystoreAlias = keystoreAlias,
            encryptionPaddings = arrayOf(
                CryptoVaultRSAEncryptionPadding.RSA_PKCS1
            ),
            signaturePaddings = arrayOf(
                CryptoVaultRSASignaturePadding.RSA_PKCS1
            )
        )
        val encrypted = try {
            cryptoVaultRSA.encrypt(
                publicKey = key.public,
                blockMode = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode.ECB,
                padding = CryptoVaultRSATransformationPadding.PKCS1Padding,
                plainText = plainText,
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, encrypted != null)
        assertEquals(true, (encrypted ?: "").isNotEmpty())

        val decrypted = try {
            cryptoVaultRSA.decrypt(
                privateKey = key.private,
                blockMode = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode.ECB,
                padding = CryptoVaultRSATransformationPadding.PKCS1Padding,
                encryptedText = encrypted!!,
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, decrypted != null)
        assertEquals(plainText, decrypted)
    }

    @Test
    fun encrypt_decrypt_non_android_keystore() {
        val plainText = "Plain RSA Text"
        val key = cryptoVaultRSA.generateKey()
        val encrypted = try {
            cryptoVaultRSA.encrypt(
                encodedPublicKey = key.publicKey,
                blockMode = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode.ECB,
                padding = CryptoVaultRSATransformationPadding.PKCS1Padding,
                plainText = plainText,
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, encrypted != null)
        assertEquals(true, (encrypted ?: "").isNotEmpty())

        val decrypted = try {
            cryptoVaultRSA.decrypt(
                encodedPrivateKey = key.privateKey,
                blockMode = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode.ECB,
                padding = CryptoVaultRSATransformationPadding.PKCS1Padding,
                encryptedText = encrypted!!,
            )
        } catch (e: Throwable) {
            null
        }
        assertEquals(true, decrypted != null)
        assertEquals(plainText, decrypted)
    }

//    @Test
//    fun failed_encrypt_with_non_public_key() {
//        val plainText = "Plain Text RSA"
//        val key = cryptoVaultRSA.generateKey()
//        val encrypted = try {
//            cryptoVaultRSA.encrypt(
//                encodedPublicKey = key.privateKey,
//                plainText = plainText,
//            )
//        } catch (e: Throwable) {
//            null
//        }
//        assertEquals(true, encrypted == null)
//    }
//
//    @Test
//    fun failed_decrypt_rsa_with_non_private_key() {
//        val plainText = "Plain Text RSA"
//        val key = cryptoVaultRSA.generateKey()
//        val encrypted = try {
//            cryptoVaultRSA.encrypt(
//                encodedPublicKey = key.publicKey,
//                plainText = plainText,
//            )
//        } catch (e: Throwable) {
//            null
//        }
//        assertEquals(true, encrypted != null)
//        val decrypted = try {
//            cryptoVaultRSA.decrypt(
//                encodedPrivateKey = key.publicKey,
//                encryptedText = encrypted!!,
//            )
//        } catch (e: Throwable) {
//            null
//        }
//        assertEquals(true, decrypted == null)
//    }
}