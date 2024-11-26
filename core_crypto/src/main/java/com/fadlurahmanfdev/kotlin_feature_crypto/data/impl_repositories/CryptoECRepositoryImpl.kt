package com.fadlurahmanfdev.kotlin_feature_crypto.data.impl_repositories

import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.data.model.CryptoKey
import com.fadlurahmanfdev.kotlin_feature_crypto.data.repositories.CryptoECRepository
import com.fadlurahmanfdev.kotlin_feature_crypto.others.BaseAsymmetricCrypto
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec

class CryptoECRepositoryImpl : BaseAsymmetricCrypto(), CryptoECRepository {
    private val algorithm = FeatureCryptoAlgorithm.EC
    private val transformation = "ECIESwithAES-CBC"

    override val whitelistedSignature: Set<FeatureCryptoSignatureAlgorithm> = setOf(
        FeatureCryptoSignatureAlgorithm.ECDSA
    )

    /**
     * Generate EC Pair Key
     *
     * @return encoded key (private & public)
     *
     * @return [CryptoKey] ]encoded key (private & public)
     * */
    override fun generateKey(): CryptoKey {
        return super.generateKey(algorithm = algorithm, keySize = null)
    }

    /**
     * Generate EC Signature
     *
     * @param encodedPrivateKey encoded private key
     * @param plainText text want to be convert into signature
     * @param signatureAlgorithm algorithm want to be used for generated signature
     *
     * @return [String] encoded signature
     *
     * @see generateKey
     * @see FeatureCryptoSignatureAlgorithm
     * */
    override fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm
    ): String {
        return super.generateSignature(
            encodedPrivateKey = encodedPrivateKey,
            algorithm = algorithm,
            plainText = plainText,
            signatureAlgorithm = signatureAlgorithm
        )
    }

    /**
     * Verify the EC signature
     *
     * @param encodedPublicKey encoded public key
     * @param signature signature want to be verified
     * @param plainText text want to be verified
     * @param signatureAlgorithm algorithm of signature want to be used
     *
     * @return [Boolean] is plain text verified with the given signature
     *
     * @see generateKey
     * @see generateSignature
     * @see FeatureCryptoSignatureAlgorithm
     * */
    override fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        signatureAlgorithm: FeatureCryptoSignatureAlgorithm
    ): Boolean {
        return super.verifySignature(
            encodedPublicKey = encodedPublicKey,
            signature = signature,
            plainText = plainText,
            algorithm = algorithm,
            signatureAlgorithm = signatureAlgorithm,
        )
    }

    /**
     * Encrypt the text
     *
     * @param encodedPublicKey encoded public key
     * @param plainText text want to be encrypted
     *
     * @return [String] encrypted text
     *
     * @see generateKey
     * */
    override fun encrypt(encodedPublicKey: String, plainText: String): String {
        Security.addProvider(BouncyCastleProvider())
        val cipher = Cipher.getInstance(transformation)
        val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
        val publicKey =
            KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name).generatePublic(publicKeySpec)
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
     * */
    override fun decrypt(encodedPrivateKey: String, encryptedText: String): String {
        Security.addProvider(BouncyCastleProvider())
        return super.decrypt(
            transformation = transformation,
            algorithm = FeatureCryptoAlgorithm.EC,
            encodedPrivateKey = encodedPrivateKey,
            encryptedText = encryptedText
        )
    }

    /**
     * Generate shared secret using our own private key & other public key.
     *
     * @param ourEncodedPrivateKey our private key in base64 encoded
     * @param otherEncodedPublicKey other channel public key in base64 encoded
     *
     * @return [String] encoded shared secret
     *
     * @see generateKey
     * */
    override fun generateSharedSecret(
        ourEncodedPrivateKey: String,
        otherEncodedPublicKey: String
    ): String {
        Security.addProvider(BouncyCastleProvider())
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        val privateKeySpec = PKCS8EncodedKeySpec(decode(ourEncodedPrivateKey))
        val privateKey = KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name)
            .generatePrivate(privateKeySpec)
        val otherPublicKeySpec = X509EncodedKeySpec(decode(otherEncodedPublicKey))
        val otherPublicKey =
            KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name)
                .generatePublic(otherPublicKeySpec)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(otherPublicKey, true)
        val sharedSecret = keyAgreement.generateSecret()
        return encode(sharedSecret)
    }

    override fun derivedSharedSecret(sharedSecret: String): String {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val keyBytes = sha256.digest(decode(sharedSecret))
        val keySpec = SecretKeySpec(keyBytes, "AES")
        return encode(keySpec.encoded)
    }
}