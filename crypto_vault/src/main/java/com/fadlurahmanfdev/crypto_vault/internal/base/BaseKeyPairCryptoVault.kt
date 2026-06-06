package com.fadlurahmanfdev.crypto_vault.internal.base

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultSignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.internal.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKey
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

abstract class BaseKeyPairCryptoVault : BaseCryptoVault() {
    open fun getPrivateKeyAndroidKeyStore(keystoreAlias: String): PrivateKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(keystoreAlias, null) as PrivateKey?
    }

    open fun getPublicAndroidKeyStore(keystoreAlias: String): PublicKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getCertificate(keystoreAlias)?.publicKey
    }

    open fun generateKey(algorithm: CryptoVaultAlgorithm, keySize: Int?): CryptoVaultKey {
        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm.name)
        if (keySize != null) {
            keyPairGenerator.initialize(keySize)
        }
        val key = keyPairGenerator.generateKeyPair()
        return CryptoVaultKey(
            privateKey = encode(key.private.encoded),
            publicKey = encode(key.public.encoded),
        )
    }

    @RequiresApi(Build.VERSION_CODES.M)
    open fun generateKeyFromAndroidKeyStore(
        algorithm: CryptoVaultAlgorithm,
        keyGenParameterSpec: KeyGenParameterSpec,
    ): KeyPair {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(algorithm.name, "AndroidKeyStore")
            keyPairGenerator.initialize(keyGenParameterSpec)
            return keyPairGenerator.generateKeyPair()
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException) {
                throw CryptoVaultExceptionCodes.strongBoxNotSupported(e.message, e)
            }
            throw CryptoVaultExceptionCodes.unknown(e.message, e)
        }
    }

    open fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        algorithm: CryptoVaultAlgorithm,
        signatureAlgorithm: CryptoVaultSignatureAlgorithm,
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(algorithm.name).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm.name)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
    }

    open fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        algorithm: CryptoVaultAlgorithm,
        signatureAlgorithm: CryptoVaultSignatureAlgorithm,
    ): Boolean {
        return try {
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance(algorithm.name).generatePublic(publicKeySpec)
            val signer = Signature.getInstance(signatureAlgorithm.name)
            signer.initVerify(publicKey)
            signer.update(plainText.toByteArray())
            signer.verify(decode(signature))
            true
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed verifySignature: ${e.message}")
            false
        }
    }

    open fun encrypt(
        transformation: String,
        algorithm: CryptoVaultAlgorithm,
        encodedPublicKey: String,
        plainText: String,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
        val publicKey = KeyFactory.getInstance(algorithm.name).generatePublic(publicKeySpec)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    open fun decrypt(
        transformation: String,
        algorithm: CryptoVaultAlgorithm,
        encodedPrivateKey: String,
        encryptedText: String,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(algorithm.name).generatePrivate(privateKeySpec)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}
