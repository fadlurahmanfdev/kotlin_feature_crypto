package com.fadlurahmanfdev.crypto_vault.internal.ec

import android.security.keystore.KeyProperties
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECOperation
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey

/**
 * Default software EC operation for ECDSA, ECIES (ECDH+HKDF+AES-GCM), and ECDH key exchange.
 *
 * Hybrid encrypt payload layout:
 * `[4-byte ephemeral public key length][ephemeral public key][12-byte IV][ciphertext]`
 */
internal class DefaultECOperation(
    private val aes: CryptoVaultAES,
) : ECOperation {
    companion object {
        const val ALGORITHM = KeyProperties.KEY_ALGORITHM_EC

        fun create(): ECOperation = DefaultECOperation(
            aes = CryptoVaultAES.create(),
        )
    }

    override fun generateKey(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM)
        keyPairGenerator.initialize(ECGenParameterSpec(EcTransformation.CURVE_NAME))
        return keyPairGenerator.generateKeyPair()
    }

    override fun generateSignature(
        privateKeyBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): ByteArray {
        val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initSign(privateKey)
        signer.update(plainTextBytes)
        return signer.sign()
    }

    override fun verifySignature(
        publicKeyBytes: ByteArray,
        signatureBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): Boolean {
        val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
        val publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(publicKeySpec)
        val signer = Signature.getInstance(signatureAlgorithm)
        signer.initVerify(publicKey)
        signer.update(plainTextBytes)
        return signer.verify(signatureBytes)
    }

    override fun encrypt(
        recipientPublicKeyBytes: ByteArray,
        plainTextBytes: ByteArray,
    ): ByteArray {
        val ephemeralKeyPair = generateKey()
        val sharedSecretBytes = generateSharedSecret(
            ephemeralPrivateKeyBytes = ephemeralKeyPair.private.encoded,
            recipientPublicKeyBytes = recipientPublicKeyBytes,
        )
        return EcECIES.encrypt(
            aes = aes,
            ephemeralKeyPair = ephemeralKeyPair,
            sharedSecretBytes = sharedSecretBytes,
            plainTextBytes = plainTextBytes,
        )
    }

    override fun decrypt(
        recipientPrivateKeyBytes: ByteArray,
        encryptedBytes: ByteArray,
    ): ByteArray {
        val envelope = EcECIES.unpack(encryptedBytes)
        val sharedSecretBytes = generateSharedSecret(
            ephemeralPrivateKeyBytes = recipientPrivateKeyBytes,
            recipientPublicKeyBytes = envelope.ephemeralPublicKeyBytes,
        )
        return EcECIES.decrypt(
            aes = aes,
            sharedSecretBytes = sharedSecretBytes,
            encryptedBytes = encryptedBytes,
        )
    }

    override fun generateSharedSecret(
        ephemeralPrivateKeyBytes: ByteArray,
        recipientPublicKeyBytes: ByteArray,
    ): ByteArray {
        val ephemeralPrivateKeySpec = PKCS8EncodedKeySpec(ephemeralPrivateKeyBytes)
        val ephemeralPrivateKey =
            KeyFactory.getInstance(ALGORITHM).generatePrivate(ephemeralPrivateKeySpec)

        val recipientPublicKeySpec = X509EncodedKeySpec(recipientPublicKeyBytes)
        val recipientPublicKey =
            KeyFactory.getInstance(ALGORITHM).generatePublic(recipientPublicKeySpec)

        val keyAgreement = KeyAgreement.getInstance(EcTransformation.KEY_AGREEMENT_ALGORITHM)
        keyAgreement.init(ephemeralPrivateKey)
        keyAgreement.doPhase(recipientPublicKey, true)
        return keyAgreement.generateSecret()
    }

    override fun deriveAESKey(
        sharedSecretBytes: ByteArray,
        saltBytes: ByteArray,
        infoBytes: ByteArray,
    ): SecretKey = EcECIES.deriveAesKey(
        sharedSecretBytes = sharedSecretBytes,
        saltBytes = saltBytes,
        infoBytes = infoBytes,
    )
}
