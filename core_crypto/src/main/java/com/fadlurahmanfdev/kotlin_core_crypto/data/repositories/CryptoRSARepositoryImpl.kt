package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import android.util.Log
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey
import com.fadlurahmanfdev.kotlin_core_crypto.others.BaseCrypto
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

class CryptoRSARepositoryImpl : BaseCrypto(), CryptoAsymmetricRepository {

    /**
     * Generate Asymmetric key
     *
     * @return [CryptoKey] encoded key (private & public)
     *
     * */
    override fun generateKey(): CryptoKey {
        val keyGen = KeyPairGenerator.getInstance(FeatureCryptoAlgorithm.RSA.name)
        keyGen.initialize(2048)
        val keyPair = keyGen.generateKeyPair()
        val publicKey = encode(keyPair.public.encoded)
        val privateKey = encode(keyPair.private.encoded)
        return CryptoKey(privateKey = privateKey, publicKey = publicKey)
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
     * @see generateKey
     * */
    override fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm
    ): String {
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey =
            KeyFactory.getInstance(FeatureCryptoAlgorithm.RSA.name).generatePrivate(privateKeySpec)
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
     * @see generateKey
     * @see FeatureCryptoSignatureAlgorithm
     *
     * */
    override fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm
    ): Boolean {
        return try {
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance(FeatureCryptoAlgorithm.RSA.name)
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
     * Encrypt the text
     *
     * @param encodedPublicKey encoded public key
     * @param plainText text want to be encrypted
     *
     * @return [Boolean] state whether text verified with the signature
     *
     * @see generateKey
     * @see FeatureCryptoSignatureAlgorithm
     *
     * */
    override fun encrypt(
        encodedPublicKey: String,
        plainText: String,
    ): String {
        val cipher =
            Cipher.getInstance("${FeatureCryptoAlgorithm.RSA.name}/${FeatureCryptoBlockMode.ECB.value}/${FeatureCryptoPadding.OAEPWithSHAAndMGF1Padding.value}")
        val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedByteArray = cipher.doFinal(plainText.toByteArray())
        return encode(encryptedByteArray)
    }

    /**
     * Decrypt the encrypted text
     *
     * @param encodedPrivateKey encoded private key
     * @param encryptedText encrypted text want to be decrypted
     *
     * @return [String] encrypted text
     *
     * @see generateKey
     * @see encrypt
     * @see FeatureCryptoSignatureAlgorithm
     *
     * */
    override fun decrypt(
        encodedPrivateKey: String,
        encryptedText: String,
    ): String {
        val cipher =
            Cipher.getInstance("${FeatureCryptoAlgorithm.RSA.name}/${FeatureCryptoBlockMode.ECB.value}/${FeatureCryptoPadding.OAEPWithSHAAndMGF1Padding.value}")
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey =
            KeyFactory.getInstance(FeatureCryptoAlgorithm.RSA.name).generatePrivate(privateKeySpec)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}