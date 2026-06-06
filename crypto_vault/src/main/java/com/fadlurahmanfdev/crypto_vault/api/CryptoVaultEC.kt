package com.fadlurahmanfdev.crypto_vault.api

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.ec.CryptoVaultECSignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.ec.CryptoVaultECTransformation
import com.fadlurahmanfdev.crypto_vault.internal.base.BaseKeyPairSigningCryptoVault
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKey
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

/**
 * Elliptic-curve vault for signing, ECIES encryption, and ECDH key exchange.
 *
 * Keystore-backed keys are stored in TEE / StrongBox when the device supports it.
 */
open class CryptoVaultEC : BaseKeyPairSigningCryptoVault() {
    private val algorithm = CryptoVaultAlgorithm.EC

    /**
     * Generates an EC key pair inside Android Keystore.
     *
     * Keys stored in Keystore cannot be exported as encoded material.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    open fun generateKeyFromAndroidKeyStore(
        keystoreAlias: String,
        strongBoxBacked: Boolean,
    ): KeyPair {
        val parameterSpec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
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
            keyGenParameterSpec = parameterSpec,
        )
    }

    /** Generates a software EC key pair encoded as Base64. */
    open fun generateKey(): CryptoVaultKey = generateKey(algorithm = algorithm, keySize = null)

    open fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        signatureAlgorithm: CryptoVaultECSignatureAlgorithm,
    ): String = generateSignature(
        encodedPrivateKey = encodedPrivateKey,
        plainText = plainText,
        algorithm = algorithm,
        signatureAlgorithm = signatureAlgorithm.value,
    )

    open fun generateSignature(
        privateKey: PrivateKey,
        plainText: String,
        signatureAlgorithm: CryptoVaultECSignatureAlgorithm,
    ): String = generateSignature(
        privateKey = privateKey,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm.value,
    )

    open fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        signatureAlgorithm: CryptoVaultECSignatureAlgorithm,
    ): Boolean = verifySignature(
        encodedPublicKey = encodedPublicKey,
        signature = signature,
        plainText = plainText,
        algorithm = algorithm,
        signatureAlgorithm = signatureAlgorithm.value,
    )

    open fun verifySignature(
        publicKey: PublicKey,
        signature: String,
        plainText: String,
        signatureAlgorithm: CryptoVaultECSignatureAlgorithm,
    ): Boolean = verifySignature(
        publicKey = publicKey,
        signature = signature,
        plainText = plainText,
        signatureAlgorithm = signatureAlgorithm.value,
    )

    open fun encrypt(
        encodedPublicKey: String,
        transformation: CryptoVaultECTransformation,
        plainText: String,
    ): String {
        Security.addProvider(BouncyCastleProvider())
        val cipher = Cipher.getInstance(transformation.value)
        val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
        val publicKey = KeyFactory.getInstance(CryptoVaultAlgorithm.EC.name).generatePublic(publicKeySpec)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    open fun decrypt(
        encodedPrivateKey: String,
        transformation: CryptoVaultECTransformation,
        encryptedText: String,
    ): String {
        Security.addProvider(BouncyCastleProvider())
        val cipher = Cipher.getInstance(transformation.value)
        val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
        val privateKey = KeyFactory.getInstance(algorithm.name).generatePrivate(privateKeySpec)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(decode(encryptedText)))
    }

    /** Derives a shared secret via ECDH from local private and remote public keys. */
    open fun generateSharedSecret(
        ourEncodedPrivateKey: String,
        otherEncodedPublicKey: String,
    ): String {
        Security.addProvider(BouncyCastleProvider())
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        val privateKeySpec = PKCS8EncodedKeySpec(decode(ourEncodedPrivateKey))
        val privateKey = KeyFactory.getInstance(CryptoVaultAlgorithm.EC.name).generatePrivate(privateKeySpec)
        val otherPublicKeySpec = X509EncodedKeySpec(decode(otherEncodedPublicKey))
        val otherPublicKey = KeyFactory.getInstance(CryptoVaultAlgorithm.EC.name).generatePublic(otherPublicKeySpec)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(otherPublicKey, true)
        return encode(keyAgreement.generateSecret())
    }

    /** Derives a 256-bit AES key from an ECDH shared secret using SHA-256. */
    open fun derivedSharedSecret(sharedSecret: String): String {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val keyBytes = sha256.digest(decode(sharedSecret))
        return encode(SecretKeySpec(keyBytes, "AES").encoded)
    }
}
