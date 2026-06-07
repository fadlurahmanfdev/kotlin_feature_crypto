package com.fadlurahmanfdev.crypto_vault.api

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.rsa.CryptoVaultRSAEncryptionPadding
import com.fadlurahmanfdev.crypto_vault.enum.rsa.CryptoVaultRSASignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.rsa.CryptoVaultRSASignaturePadding
import com.fadlurahmanfdev.crypto_vault.enum.rsa.CryptoVaultRSATransformationMode
import com.fadlurahmanfdev.crypto_vault.enum.rsa.CryptoVaultRSATransformationPadding
import com.fadlurahmanfdev.crypto_vault.internal.base.BaseKeyPairCryptoVault
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKey
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * RSA encryption and signature vault with optional Android Keystore backing.
 */
open class CryptoVaultRSA : BaseKeyPairCryptoVault() {
    private val algorithm = CryptoVaultAlgorithm.RSA

    /** Generates a 2048-bit RSA key pair encoded as Base64. */
    open fun generateKey(): CryptoVaultKey = super.generateKey(algorithm, 2048)

    /**
     * Generates an RSA key pair inside Android Keystore.
     *
     * @param keystoreAlias Key identifier stored in Android Keystore.
     * @param encryptionPaddings Supported RSA encryption paddings for this key.
     * @param signaturePaddings Supported RSA signature paddings for this key.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    open fun generateKeyFromAndroidKeyStore(
        keystoreAlias: String,
        encryptionPaddings: Array<CryptoVaultRSAEncryptionPadding>? = null,
        signaturePaddings: Array<CryptoVaultRSASignaturePadding>? = null,
    ): KeyPair {
        val parameterSpec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        ).setDigests(
            KeyProperties.DIGEST_SHA1,
            KeyProperties.DIGEST_SHA256,
            KeyProperties.DIGEST_SHA512,
            KeyProperties.DIGEST_MD5,
        ).apply {
            if (!encryptionPaddings.isNullOrEmpty()) {
                setEncryptionPaddings(*encryptionPaddings.map { it.value }.toTypedArray())
            }
            if (!signaturePaddings.isNullOrEmpty()) {
                setSignaturePaddings(*signaturePaddings.map { it.value }.toTypedArray())
            }
        }.build()

        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm.name, "AndroidKeyStore")
        keyPairGenerator.initialize(parameterSpec)
        return keyPairGenerator.generateKeyPair()
    }

    open fun generateSignature(
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

    open fun generateSignature(
        privateKey: PrivateKey,
        signatureAlgorithm: CryptoVaultRSASignatureAlgorithm,
        plainText: String,
    ): String {
        val signer = Signature.getInstance(signatureAlgorithm.name)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
    }

    open fun verifySignature(
        encodedPublicKey: String,
        signatureAlgorithm: CryptoVaultRSASignatureAlgorithm,
        signature: String,
        plainText: String,
    ): Boolean {
        return try {
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance(CryptoVaultAlgorithm.RSA.name).generatePublic(publicKeySpec)
            val signer = Signature.getInstance(signatureAlgorithm.name)
            signer.initVerify(publicKey)
            signer.update(plainText.toByteArray())
            signer.verify(decode(signature))
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed verifySignature: ${e.message}")
            false
        }
    }

    open fun verifySignature(
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
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed verifySignature: ${e.message}", e)
            false
        }
    }

    open fun encrypt(
        publicKey: PublicKey,
        blockMode: CryptoVaultRSATransformationMode,
        padding: CryptoVaultRSATransformationPadding,
        plainText: String,
    ): String {
        val cipher = Cipher.getInstance(buildTransformation(blockMode, padding))
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    open fun encrypt(
        encodedPublicKey: String,
        blockMode: CryptoVaultRSATransformationMode,
        padding: CryptoVaultRSATransformationPadding,
        plainText: String,
    ): String {
        val cipher = Cipher.getInstance(buildTransformation(blockMode, padding))
        val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
        val publicKey = KeyFactory.getInstance(algorithm.name).generatePublic(publicKeySpec)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    open fun decrypt(
        privateKey: PrivateKey,
        blockMode: CryptoVaultRSATransformationMode,
        padding: CryptoVaultRSATransformationPadding,
        encryptedText: String,
    ): String {
        val cipher = Cipher.getInstance(buildTransformation(blockMode, padding))
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(decode(encryptedText)))
    }

    open fun decrypt(
        encodedPrivateKey: String,
        blockMode: CryptoVaultRSATransformationMode,
        padding: CryptoVaultRSATransformationPadding,
        encryptedText: String,
    ): String {
        val cipher = Cipher.getInstance(buildTransformation(blockMode, padding))
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(CryptoVaultAlgorithm.RSA.name).generatePrivate(privateKeySpec)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(decode(encryptedText)))
    }

    private fun buildTransformation(
        blockMode: CryptoVaultRSATransformationMode,
        padding: CryptoVaultRSATransformationPadding,
    ): String = "RSA/${blockMode.value}/${padding.value}"
}
