package com.fadlurahmanfdev.kotlin_feature_crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.kotlin_feature_crypto.base.BaseKeyPairSigningCryptoVault
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECTransformation
import com.fadlurahmanfdev.kotlin_feature_crypto.data.model.CryptoVaultKey
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec

class CryptoVaultEC : BaseKeyPairSigningCryptoVault() {
    private val algorithm = com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm.EC

    /**
     * Generate EC Key Pair from Android KeyStore.
     *
     * EC Key pair from Android Keystore cannot be decode.
     *
     * @param keystoreAlias key identifier.
     * @param strongBoxBacked Sets whether this key should be protected by a StrongBox security chip.
     * */
    @RequiresApi(Build.VERSION_CODES.M)
    fun generateKeyFromAndroidKeyStore(
        keystoreAlias: String,
        strongBoxBacked: Boolean,
    ): KeyPair {
        val parameterSpec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).setDigests(
            KeyProperties.DIGEST_SHA256,
            KeyProperties.DIGEST_SHA512,
        ).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(strongBoxBacked)
            }
        }.build()

        return generateKeyFromAndroidKeyStore(
            algorithm = algorithm,
            keyGenParameterSpec = parameterSpec
        )
    }

    /**
     * Generate EC Pair Key
     *
     * @return [CryptoVaultKey] encoded EC Key Pair (private & public)
     *
     * */
    fun generateKey(): CryptoVaultKey = generateKey(algorithm = algorithm, keySize = null)

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
     * */
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        signatureAlgorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm,
    ): String = generateSignature(
        encodedPrivateKey = encodedPrivateKey,
        plainText = plainText,
        algorithm = algorithm,
        signatureAlgorithm = signatureAlgorithm.value,
    )

    /**
     * Generate Signature using private key
     *
     * @param privateKey private key get from Android Keystore
     * @param plainText text want to be convert into signature
     * @param signatureAlgorithm algorithm want to be used for generated signature
     *
     * @return [String] encoded signature
     * */
    fun generateSignature(
        privateKey: PrivateKey,
        plainText: String,
        signatureAlgorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm,
    ): String = generateSignature(
        privateKey = privateKey,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm.value,
    )

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
     * @see CryptoVaultSignatureAlgorithm
     * */
    fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        signatureAlgorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm,
    ): Boolean = verifySignature(
        encodedPublicKey = encodedPublicKey,
        signature = signature,
        plainText = plainText,
        algorithm = algorithm,
        signatureAlgorithm = signatureAlgorithm.value,
    )

    /**
     * Verify the signature using public key from Android Keystore.
     *
     * @param publicKey public key generated from Android KeyStore.
     * @param signature signature want to be verified.
     * @param plainText text want to be verified.
     * @param signatureAlgorithm algorithm of signature want to be used.
     *
     * @return [Boolean] if plain text match with the given signature.
     * */
    fun verifySignature(
        publicKey: PublicKey,
        signature: String,
        plainText: String,
        signatureAlgorithm: com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm,
    ): Boolean = verifySignature(
        publicKey = publicKey,
        signature = signature,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm.value,
    )

    /**
     * Encrypt plain text using encoded public key
     *
     * @param encodedPublicKey encoded public key
     * @param transformation transformation of encrypted text
     * @param plainText text want to be encrypted
     *
     * @return [String] encrypted text
     *
     * @see generateKey
     * */
    fun encrypt(
        encodedPublicKey: String,
        transformation: com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECTransformation,
        plainText: String,
    ): String {
        Security.addProvider(BouncyCastleProvider())
        val cipher = Cipher.getInstance(transformation.value)
        val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
        val publicKey =
            KeyFactory.getInstance(com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm.EC.name).generatePublic(publicKeySpec)
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
    fun decrypt(
        encodedPrivateKey: String,
        transformation: com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECTransformation,
        encryptedText: String,
    ): String {
        Security.addProvider(BouncyCastleProvider())
        val cipher = Cipher.getInstance(transformation.value)
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(algorithm.name).generatePrivate(privateKeySpec)
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
    fun generateSharedSecret(
        ourEncodedPrivateKey: String,
        otherEncodedPublicKey: String,
    ): String {
        Security.addProvider(BouncyCastleProvider())
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        val privateKeySpec = PKCS8EncodedKeySpec(decode(ourEncodedPrivateKey))
        val privateKey = KeyFactory.getInstance(com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm.EC.name)
            .generatePrivate(privateKeySpec)
        val otherPublicKeySpec = X509EncodedKeySpec(decode(otherEncodedPublicKey))
        val otherPublicKey =
            KeyFactory.getInstance(com.fadlurahmanfdev.kotlin_feature_crypto.enums.CryptoVaultAlgorithm.EC.name)
                .generatePublic(otherPublicKeySpec)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(otherPublicKey, true)
        val sharedSecret = keyAgreement.generateSecret()
        return encode(sharedSecret)
    }

    /**
     * Generate AES Key from shared secret
     *
     * @param sharedSecret shared secret generated from [generateSharedSecret]
     *
     * @return [String] encoded AES Key
     *
     * @see generateSharedSecret
     * */
    fun derivedSharedSecret(sharedSecret: String): String {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val keyBytes = sha256.digest(decode(sharedSecret))
        val keySpec = SecretKeySpec(keyBytes, "AES")
        return encode(keySpec.encoded)
    }
}