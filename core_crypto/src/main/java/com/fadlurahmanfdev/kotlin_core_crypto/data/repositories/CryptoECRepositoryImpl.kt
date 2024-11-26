package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import android.util.Log
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.enums.FeatureCryptoSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey
import com.fadlurahmanfdev.kotlin_core_crypto.others.BaseAsymmetricCrypto
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Security
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec

class CryptoECRepositoryImpl : BaseAsymmetricCrypto(), CryptoECRepository {
    /**
     * Generate EC Pair Key
     *
     * @return encoded key (private & public)
     *
     * @return [CryptoKey] ]encoded key (private & public)
     * */
    override fun generateKey(): CryptoKey {
        val keyPairGenerator = KeyPairGenerator.getInstance(FeatureCryptoAlgorithm.EC.name)
        val keyPair = keyPairGenerator.generateKeyPair()
        return CryptoKey(
            privateKey = encode(keyPair.private.encoded),
            publicKey = encode(keyPair.public.encoded)
        )
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
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey =
            KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm.name)
        signer.initSign(privateKey)
        signer.update(plainText.toByteArray())
        return encode(signer.sign())
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
        return try {
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name)
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
     * @return [String] encrypted text
     *
     * @see generateKey
     * */
    override fun encrypt(encodedPublicKey: String, plainText: String): String {
        Security.addProvider(BouncyCastleProvider())
        val cipher =
            Cipher.getInstance("ECIESwithAES-CBC")
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
        val cipher =
            Cipher.getInstance("ECIESwithAES-CBC")
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey =
            KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name).generatePrivate(privateKeySpec)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(decode(encryptedText)))
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
    override fun generateSharedSecret(ourEncodedPrivateKey: String, otherEncodedPublicKey: String): String {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        val privateKeySpec = PKCS8EncodedKeySpec(decode(ourEncodedPrivateKey))
        val privateKey = KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name)
            .generatePrivate(privateKeySpec)
        val otherPublicKeySpec = X509EncodedKeySpec(decode(otherEncodedPublicKey))
        val otherPublicKey =
            KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name)
                .generatePublic(otherPublicKeySpec)
        keyAgreement.init(privateKey)
        val sharedSecretKey = keyAgreement.doPhase(otherPublicKey, true)
        return encode(sharedSecretKey.encoded)
    }

    private fun test() {
        val aliceKey = generateKey()
        println("MASUK ALICE PRIVATE KEY: ${aliceKey.privateKey}")
        println("MASUK ALICE PUBLIC KEY: ${aliceKey.publicKey}")
        val bobKey = generateKey()
        println("MASUK BOB PRIVATE KEY: ${bobKey.privateKey}")
        println("MASUK bob PUBLIC KEY: ${bobKey.publicKey}")

        val aliceKeyAgreement = KeyAgreement.getInstance("ECDH")
        val alicePrivateKeySpec = PKCS8EncodedKeySpec(decode(aliceKey.privateKey))
        val alicePrivateKey = KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name)
            .generatePrivate(alicePrivateKeySpec)
        val bobPublicKeySpec = X509EncodedKeySpec(decode(bobKey.publicKey))
        val bobPublicKey =
            KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name).generatePublic(bobPublicKeySpec)
        aliceKeyAgreement.init(alicePrivateKey)
        aliceKeyAgreement.doPhase(bobPublicKey, true)

        val aliceSharedSecret = aliceKeyAgreement.generateSecret()

        val bobKeyAgreement = KeyAgreement.getInstance("ECDH")
        val bobPrivateKeySpec = PKCS8EncodedKeySpec(decode(bobKey.privateKey))
        val bobPrivateKey = KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name)
            .generatePrivate(bobPrivateKeySpec)
        val alicePublicKeySpec = X509EncodedKeySpec(decode(aliceKey.publicKey))
        val alicePublicKey = KeyFactory.getInstance(FeatureCryptoAlgorithm.EC.name)
            .generatePublic(alicePublicKeySpec)
        bobKeyAgreement.init(bobPrivateKey)
        bobKeyAgreement.doPhase(alicePublicKey, true)

        val bobSharedSecret = bobKeyAgreement.generateSecret()

        println("Alice's Shared Secret: ${encode(aliceSharedSecret)}")
        println("Bob's Shared Secret: ${encode(bobSharedSecret)}")

        val sha256 = MessageDigest.getInstance("SHA-256")
        val aliceKeyBytes = sha256.digest(aliceSharedSecret)
        val aliceKeySpec = SecretKeySpec(aliceKeyBytes, "AES")

        println("KEY: ${encode(aliceKeySpec.encoded)}")

        val cryptoAESRepositoryImpl = CryptoAESRepositoryImpl()
        val ivKey = cryptoAESRepositoryImpl.generateIVKey()
        println("IV KEY: $ivKey")

        val encryptedText = cryptoAESRepositoryImpl.encrypt(
            key = encode(aliceKeySpec.encoded),
            ivKey = ivKey,
            plainText = "P4ssw0rd!Sus4h",

            )
        println("ENCRYPTED TEXT: $encryptedText")
        val decryptedText = cryptoAESRepositoryImpl.decrypt(
            key = encode(aliceKeySpec.encoded),
            ivKey = ivKey,
            encryptedText = encryptedText,
        )
        println("DECRYPTED TEXT: $decryptedText")
    }
}