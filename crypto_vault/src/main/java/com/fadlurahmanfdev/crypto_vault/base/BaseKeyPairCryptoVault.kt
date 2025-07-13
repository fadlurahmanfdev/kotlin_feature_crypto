package com.fadlurahmanfdev.crypto_vault.base

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.data.model.CryptoVaultKey
import com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultBlockMode
import com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultPadding
import com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultSignatureAlgorithm
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

/**
 * Abstract class for asymmetric cryptography
 * */
abstract class BaseKeyPairCryptoVault : BaseCryptoVault() {
    /**
     * Load Private Key from Android KeyStore.
     *
     * @param keystoreAlias unique identifier of key.
     *
     * if the key is not exist in Android KeyStore, it will return null.
     * */
    fun getPrivateKeyAndroidKeyStore(keystoreAlias: String): PrivateKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(keystoreAlias, null) as PrivateKey?
    }

    /**
     * Load Public Key from Android KeyStore.
     *
     * @param keystoreAlias unique identifier of key.
     *
     * if the key is not exist in Android KeyStore, it will return null.
     * */
    fun getPublicAndroidKeyStore(keystoreAlias: String): PublicKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getCertificate(keystoreAlias)?.publicKey
    }

    /**
     * Generate key pair for asymmetric cryptography
     *
     * @param algorithm algorithm used for generate key
     *
     * @return [CryptoVaultKey] - encoded key pair (private & public)
     * */
    fun generateKey(algorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm, keySize: Int?): CryptoVaultKey {
        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm.name)
        if (keySize != null) {
            keyPairGenerator.initialize(keySize)
        }
        val key = keyPairGenerator.generateKeyPair()
        return CryptoVaultKey(
            privateKey = encode(key.private.encoded),
            publicKey = encode(key.public.encoded)
        )
    }

    /**
     * Generate Key Pair from Android KeyStore.
     *
     * @param algorithm encryption algorithm for the key pair.
     * @param keyGenParameterSpec specification for key.
     *
     * @return [KeyPair] keypair that cannot be decoded because, it safely store in Android KeyStore.
     * */
    @RequiresApi(Build.VERSION_CODES.M)
    fun generateKeyFromAndroidKeyStore(
        algorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm,
        keyGenParameterSpec: KeyGenParameterSpec,
    ): KeyPair {
        try {
            val keyPairGenerator =
                KeyPairGenerator.getInstance(algorithm.name, "AndroidKeyStore")
            keyPairGenerator.initialize(keyGenParameterSpec)
            return keyPairGenerator.generateKeyPair()
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (e is StrongBoxUnavailableException) {
                    throw com.fadlurahmanfdev.crypto_vault.constant.CryptoVaultExceptionConstant.STRONG_BOX_NOT_SUPPORTED.copy(message = e.message)
                }
            }
            throw com.fadlurahmanfdev.crypto_vault.constant.CryptoVaultExceptionConstant.UNKNOWN.copy(message = e.message)
        }
    }

    /**
     * Generate signature later maybe want to be verified
     *
     * @param encodedPrivateKey encoded private key
     * @param plainText text want to be convert into a signature
     * @param algorithm algorithm used for the signature
     * @param signatureAlgorithm signature of the algorithm
     *
     * @return encoded signature
     *
     * @see generateKey
     * @see CryptoVaultAlgorithm
     * @see CryptoVaultSignatureAlgorithm
     * */
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        algorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm,
        signatureAlgorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultSignatureAlgorithm,
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(algorithm.name).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm.name)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
    }

    /**
     * Verify the generated signature
     *
     * @param encodedPublicKey encoded public key
     * @param plainText text want to be convert into a signature
     * @param algorithm algorithm used for the signature
     * @param signatureAlgorithm signature of the algorithm
     *
     * @return [Boolean] state whether signature is verified
     *
     * @see generateKey
     * @see generateSignature
     * @see CryptoVaultAlgorithm
     * @see CryptoVaultSignatureAlgorithm
     * */
    fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        algorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm,
        signatureAlgorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultSignatureAlgorithm
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

    /**
     * Encrypt the text
     *
     * @param algorithm algorithm used for encryption
     * @param transformation transformation used for encryption
     * @param encodedPublicKey encoded public key
     * @param plainText text want to be convert into a signature
     *
     * @return encrypted text
     *
     * @see generateKey
     * @see generateSignature
     * @see CryptoVaultAlgorithm
     * @see CryptoVaultBlockMode
     * @see CryptoVaultPadding
     * */
    fun encrypt(
        transformation: String,
        algorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm,
        encodedPublicKey: String,
        plainText: String,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
        val publicKey = KeyFactory.getInstance(algorithm.name).generatePublic(publicKeySpec)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedByteArray = cipher.doFinal(plainText.toByteArray())
        return encode(encryptedByteArray)
    }

    /**
     * Decrypt the encrypted text
     *
     * @param algorithm algorithm used for decryption
     * @param transformation transformation used for decryption
     * @param encodedPrivateKey encoded private key
     * @param encryptedText text want to be decrypted into plain text
     *
     * @return encrypted text
     *
     * @see generateKey
     * @see generateSignature
     * @see CryptoVaultAlgorithm
     * @see CryptoVaultBlockMode
     * @see CryptoVaultPadding
     * */
    fun decrypt(
        transformation: String,
        algorithm: com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm,
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