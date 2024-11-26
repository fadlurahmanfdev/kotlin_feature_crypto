package com.fadlurahmanfdev.kotlin_feature_crypto.data.impl_repositories

import android.util.Log
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoBlockMode
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoPadding
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.data.model.CryptoKey
import com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories.CryptoRSARepository
import com.fadlurahmanfdev.kotlin_feature_crypto.others.BaseAsymmetricCrypto
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

class CryptoRSARepositoryImpl : BaseAsymmetricCrypto(), CryptoRSARepository {
    private val algorithm = FeatureCryptoAlgorithm.RSA


    override val whitelistedSignature: Set<FeatureCryptoSignatureAlgorithm> = setOf(
        FeatureCryptoSignatureAlgorithm.SHA1withRSA
    )

    /**
     * Generate Asymmetric key
     *
     * @return [CryptoKey] encoded key (private & public)
     *
     * */
    override fun generateKey(): CryptoKey {
        return super.generateKey(algorithm = algorithm, keySize = 2048)
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
        return super.generateSignature(
            encodedPrivateKey = encodedPrivateKey,
            plainText = plainText,
            algorithm = algorithm,
            signatureAlgorithm = signatureAlgorithm
        )
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
        return super.encrypt(
            transformation = "${FeatureCryptoAlgorithm.RSA.name}/${FeatureCryptoBlockMode.ECB.value}/${FeatureCryptoPadding.OAEPWithSHAAndMGF1Padding.value}",
            algorithm = algorithm,
            encodedPublicKey = encodedPublicKey,
            plainText = plainText
        )
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