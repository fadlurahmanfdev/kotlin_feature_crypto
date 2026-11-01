package com.fadlurahmanfdev.crypto_vault.internal.rsa

import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.domain.contracts.RSASoftwareOperation
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

internal class DefaultSoftwareRSAOperation(
    private val keyPairGeneratorFactory: () -> KeyPairGenerator = {
        KeyPairGenerator.getInstance(RsaTransformation.ALGORITHM)
    },
    private val cipherFactory: (transformation: String) -> Cipher = { transformation ->
        Cipher.getInstance(transformation)
    },
    private val signatureFactory: (algorithm: String) -> Signature = { algorithm ->
        Signature.getInstance(algorithm)
    },
    private val keyFactoryFactory: () -> KeyFactory = {
        KeyFactory.getInstance(RsaTransformation.ALGORITHM)
    },
) : RSASoftwareOperation {

    companion object {
        fun create(): DefaultSoftwareRSAOperation = DefaultSoftwareRSAOperation()
    }

    override fun generateKey(keySize: Int): KeyPair {
        if (keySize !in RsaTransformation.SUPPORTED_KEY_SIZES) {
            throw CryptoVaultExceptionCodes.invalidKeySize(
                message = "RSA key size must be one of ${RsaTransformation.SUPPORTED_KEY_SIZES}, but was $keySize",
            )
        }
        return try {
            val keyPairGenerator = keyPairGeneratorFactory()
            keyPairGenerator.initialize(keySize)
            keyPairGenerator.generateKeyPair()
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to generate RSA key pair: ${e.message}",
                cause = e,
            )
        }
    }

    override fun parsePublicKey(publicKeyBytes: ByteArray): PublicKey {
        return try {
            keyFactoryFactory().generatePublic(X509EncodedKeySpec(publicKeyBytes))
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to parse RSA public key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun parsePrivateKey(privateKeyBytes: ByteArray): PrivateKey {
        return try {
            keyFactoryFactory().generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to parse RSA private key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun encrypt(
        publicKey: PublicKey,
        plainTextBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        val oaepSpec = RsaCipherHelper.oaepParameterSpecForPadding(padding)
        return if (oaepSpec != null) {
            encrypt(publicKey, plainTextBytes, blockMode, padding, oaepSpec)
        } else {
            encryptWithoutSpec(publicKey, plainTextBytes, blockMode, padding)
        }
    }

    override fun encrypt(
        publicKey: PublicKey,
        plainTextBytes: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(RsaTransformation.raw(blockMode, padding))
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, algorithmParameterSpec)
            cipher.doFinal(plainTextBytes)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to encrypt with software RSA key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun decrypt(
        privateKey: PrivateKey,
        encryptedBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        val oaepSpec = RsaCipherHelper.oaepParameterSpecForPadding(padding)
        return if (oaepSpec != null) {
            decrypt(privateKey, encryptedBytes, blockMode, padding, oaepSpec)
        } else {
            decryptWithoutSpec(privateKey, encryptedBytes, blockMode, padding)
        }
    }

    override fun decrypt(
        privateKey: PrivateKey,
        encryptedBytes: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(RsaTransformation.raw(blockMode, padding))
            cipher.init(Cipher.DECRYPT_MODE, privateKey, algorithmParameterSpec)
            cipher.doFinal(encryptedBytes)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to decrypt with software RSA key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun sign(
        privateKey: PrivateKey,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): ByteArray {
        return try {
            val signer = signatureFactory(signatureAlgorithm)
            signer.initSign(privateKey)
            signer.update(plainTextBytes)
            signer.sign()
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to sign with software RSA key: ${e.message}",
                cause = e,
            )
        }
    }

    override fun verify(
        publicKey: PublicKey,
        signatureBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): Boolean {
        return try {
            val verifier = signatureFactory(signatureAlgorithm)
            verifier.initVerify(publicKey)
            verifier.update(plainTextBytes)
            verifier.verify(signatureBytes)
        } catch (e: SignatureException) {
            false
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to verify RSA signature: ${e.message}",
                cause = e,
            )
        }
    }

    private fun encryptWithoutSpec(
        publicKey: PublicKey,
        plainTextBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(RsaTransformation.raw(blockMode, padding))
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            cipher.doFinal(plainTextBytes)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to encrypt with software RSA key: ${e.message}",
                cause = e,
            )
        }
    }

    private fun decryptWithoutSpec(
        privateKey: PrivateKey,
        encryptedBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(RsaTransformation.raw(blockMode, padding))
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            cipher.doFinal(encryptedBytes)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to decrypt with software RSA key: ${e.message}",
                cause = e,
            )
        }
    }
}
