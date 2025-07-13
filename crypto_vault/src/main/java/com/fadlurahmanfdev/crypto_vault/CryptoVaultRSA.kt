package com.fadlurahmanfdev.crypto_vault

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.base.BaseKeyPairCryptoVault
import com.fadlurahmanfdev.crypto_vault.data.model.CryptoVaultKey
import com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultPadding.*
import com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultSignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSAEncryptionPadding
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSAEncryptionPadding.*
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSASignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSASignaturePadding
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSASignaturePadding.*
import com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationPadding
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

class CryptoVaultRSA : BaseKeyPairCryptoVault() {
    private val algorithm = com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm.RSA

    /**
     * Generate RSA Key
     *
     * @return [CryptoVaultKey] encoded key (private key & public key)
     *
     * */
    fun generateKey(): CryptoVaultKey {
        return super.generateKey(algorithm, 2048)
    }

    /**
     * Generate RSA Key via AndroidKeyStore
     *
     * @return [CryptoVaultKey] encoded key (private key & public key)
     *
     * */


    @RequiresApi(Build.VERSION_CODES.M)
    fun generateKeyFromAndroidKeyStore(
        keystoreAlias: String,
        encryptionPaddings: Array<CryptoVaultRSAEncryptionPadding>? = null,
        signaturePaddings: Array<CryptoVaultRSASignaturePadding>? = null,
    ): KeyPair {

        val parameterSpec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).setDigests(
            KeyProperties.DIGEST_SHA1,
            KeyProperties.DIGEST_SHA256,
            KeyProperties.DIGEST_SHA512,
            KeyProperties.DIGEST_MD5
        )
            .apply {
                if (!encryptionPaddings.isNullOrEmpty()) {
                    setEncryptionPaddings(*encryptionPaddings.map { it.value }.toTypedArray())
                }

                if (!signaturePaddings.isNullOrEmpty()) {
                    setSignaturePaddings(*signaturePaddings.map { it.value }.toTypedArray())
                }
            }
            .build()

        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm.name, "AndroidKeyStore")
        keyPairGenerator.initialize(parameterSpec)
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * Generate Signature
     *
     * @param encodedPrivateKey encoded private key
     * @param plainText text want to be convert into signature
     * @param signatureAlgorithm algorithm used for generate signature
     *
     * @return [String] encoded signature
     *
     * @see generateKeyFromAndroidKeyStore
     * */
    fun generateSignature(
        encodedPrivateKey: String,
        signatureAlgorithm: CryptoVaultRSASignatureAlgorithm,
        plainText: String,
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(algorithm.name).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm.name)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
    }

    /**
     * Generate Signature
     *
     * @param encodedPrivateKey encoded private key
     * @param plainText text want to be convert into signature
     * @param signatureAlgorithm algorithm used for generate signature
     *
     * @return [String] encoded signature
     *
     * @see generateKeyFromAndroidKeyStore
     * */
    fun generateSignature(
        privateKey: PrivateKey,
        signatureAlgorithm: CryptoVaultRSASignatureAlgorithm,
        plainText: String,
    ): String {
        val signer = Signature.getInstance(signatureAlgorithm.name)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
    }

    /**
     * Verify signature
     *
     * @param encodedPublicKey encoded public key
     * @param signature encoded signature want to be verified
     * @param plainText text want to be verified
     * @param signatureAlgorithm algorithm used for generate signature
     *
     * @return [Boolean] state whether text verified with the signature
     *
     * @see generateKeyFromAndroidKeyStore
     * @see CryptoVaultSignatureAlgorithm
     *
     * */
    fun verifySignature(
        encodedPublicKey: String,
        signatureAlgorithm: CryptoVaultRSASignatureAlgorithm,
        signature: String,
        plainText: String,
    ): Boolean {
        return try {
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance(com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm.RSA.name)
                .generatePublic(publicKeySpec)
            val signer = Signature.getInstance(signatureAlgorithm.name)
            signer.initVerify(publicKey)
            signer.update(plainText.toByteArray())
            signer.verify(decode(signature))
            true
        } catch (e: Throwable) {
            Log.e(
                this::class.java.simpleName,
                "failed verifySignature: ${e.message}"
            )
            false
        }
    }

    /**
     * Verify signature
     *
     * @param publicKey public key via Android KeyStore.
     * @param signature encoded signature want to be verified
     * @param plainText text want to be verified
     * @param signatureAlgorithm algorithm used for generate signature
     *
     * @return [Boolean] state whether text verified with the signature
     *
     * @see generateKeyFromAndroidKeyStore
     * @see CryptoVaultSignatureAlgorithm
     *
     * */
    fun verifySignature(
        publicKey: PublicKey,
        signatureAlgorithm: CryptoVaultRSASignatureAlgorithm,
        signature: String,
        plainText: String,
    ): Boolean {
        return try {
            val signer = Signature.getInstance(signatureAlgorithm.name)
            signer.initVerify(publicKey)
            signer.update(plainText.toByteArray())
            signer.verify(decode(signature))
            true
        } catch (e: Throwable) {
            Log.e(
                this::class.java.simpleName,
                "failed verifySignature: ${e.message}",
                e
            )
            false
        }
    }

    /**
     * Encrypt the text
     *
     * @param publicKey public key that generated from [generateKeyFromAndroidKeyStore] or [generateKey] or get from [getPublicAndroidKeyStore]
     * @param plainText text want to be encrypted
     *
     * @return [Boolean] state whether text verified with the signature
     *
     * @see generateKeyFromAndroidKeyStore
     * @see CryptoVaultSignatureAlgorithm
     *
     * */
    fun encrypt(
        publicKey: PublicKey,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode,
        padding: CryptoVaultRSATransformationPadding,
        plainText: String,
    ): String {
        val cipher =
            Cipher.getInstance("RSA/${blockMode.value}/${padding.value}")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    /**
     * Encrypt the text
     *
     * @param publicKey public key that generated from [generateKeyFromAndroidKeyStore] or [generateKey] or get from [getPublicAndroidKeyStore]
     * @param plainText text want to be encrypted
     *
     * @return [Boolean] state whether text verified with the signature
     *
     * @see generateKeyFromAndroidKeyStore
     * @see CryptoVaultSignatureAlgorithm
     *
     * */
    fun encrypt(
        encodedPublicKey: String,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode,
        padding: CryptoVaultRSATransformationPadding,
        plainText: String,
    ): String {
        val cipher =
            Cipher.getInstance("RSA/${blockMode.value}/${padding.value}")
        val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
        val publicKey = KeyFactory.getInstance(algorithm.name).generatePublic(publicKeySpec)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    fun decrypt(
        privateKey: PrivateKey,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode,
        padding: CryptoVaultRSATransformationPadding,
        encryptedText: String,
    ): String {
        val cipher =
            Cipher.getInstance("RSA/${blockMode.value}/${padding.value}")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(decode(encryptedText)))
    }

    /**
     * Decrypt the encrypted text
     *
     * @param encodedPrivateKey encoded private key
     * @param encryptedText encrypted text want to be decrypted
     *
     * @return [String] encrypted text
     *
     * @see generateKeyFromAndroidKeyStore
     * @see CryptoVaultSignatureAlgorithm
     *
     * */
    fun decrypt(
        encodedPrivateKey: String,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode,
        padding: CryptoVaultRSATransformationPadding,
        encryptedText: String,
    ): String {
        val cipher =
            Cipher.getInstance("RSA/${blockMode.value}/${padding.value}")
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey =
            KeyFactory.getInstance(com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm.RSA.name).generatePrivate(privateKeySpec)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}