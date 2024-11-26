package com.fadlurahmanfdev.kotlin_core_crypto.others

import android.util.Log
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * Abstract class for asymmetric cryptography
 * */
abstract class BaseAsymmetricCrypto : BaseCrypto() {

    abstract val whitelistedSignature: Set<FeatureCryptoSignatureAlgorithm>

    /**
     * Generate key pair for asymmetric cryptography
     *
     * @param algorithm algorithm used for generate key
     *
     * @return [CryptoKey] - encoded key pair (private & public)
     * */
    fun generateKey(algorithm: FeatureCryptoAlgorithm, keySize: Int?): CryptoKey {
        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm.name)
        if (keySize != null) {
            keyPairGenerator.initialize(keySize)
        }
        val key = keyPairGenerator.generateKeyPair()
        return CryptoKey(
            privateKey = encode(key.private.encoded),
            publicKey = encode(key.public.encoded)
        )
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
     * @see FeatureCryptoAlgorithm
     * @see FeatureCryptoSignatureAlgorithm
     * */
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        algorithm: FeatureCryptoAlgorithm,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm,
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
     * @see FeatureCryptoAlgorithm
     * @see FeatureCryptoSignatureAlgorithm
     * */
    fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        algorithm: FeatureCryptoAlgorithm,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm
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
     * @see FeatureCryptoAlgorithm
     * @see FeatureCryptoBlockMode
     * @see FeatureCryptoPadding
     * */
    fun encrypt(
        transformation: String,
        algorithm: FeatureCryptoAlgorithm,
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
     * @see FeatureCryptoAlgorithm
     * @see FeatureCryptoBlockMode
     * @see FeatureCryptoPadding
     * */
    fun decrypt(
        transformation: String,
        algorithm: FeatureCryptoAlgorithm,
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