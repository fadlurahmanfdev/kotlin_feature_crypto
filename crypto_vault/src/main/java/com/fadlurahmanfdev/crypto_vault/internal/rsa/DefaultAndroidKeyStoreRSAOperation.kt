package com.fadlurahmanfdev.crypto_vault.internal.rsa

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.domain.contracts.RSAAndroidKeyStoreOperation
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher

internal class DefaultAndroidKeyStoreRSAOperation(
    private val keyPairGeneratorFactory: () -> KeyPairGenerator = {
        KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            RsaTransformation.KEYSTORE_PROVIDER,
        )
    },
    private val cipherFactory: (transformation: String) -> Cipher = { transformation ->
        Cipher.getInstance(transformation)
    },
    private val signatureFactory: (algorithm: String) -> Signature = { algorithm ->
        Signature.getInstance(algorithm)
    },
) : RSAAndroidKeyStoreOperation {

    companion object {
        fun create(): DefaultAndroidKeyStoreRSAOperation = DefaultAndroidKeyStoreRSAOperation()
    }

    private fun keyStoreInstance() = KeyStore.getInstance(RsaTransformation.KEYSTORE_PROVIDER)

    override fun generateKey(
        keyStoreAlias: String,
        keySize: Int,
        encryptionPaddings: Array<String>,
        signaturePaddings: Array<String>,
        digests: Array<String>,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit,
    ): KeyPair {
        if (keyStoreAlias.isBlank()) {
            throw CryptoVaultExceptionCodes.invalidKeyAlias(
                message = "Keystore alias must not be blank",
            )
        }
        if (keySize !in RsaTransformation.SUPPORTED_KEY_SIZES) {
            throw CryptoVaultExceptionCodes.invalidKeySize(
                message = "RSA key size must be one of ${RsaTransformation.SUPPORTED_KEY_SIZES}, but was $keySize",
            )
        }
        return try {
            val purposes =
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY

            val keyGenParameterSpec = KeyGenParameterSpec
                .Builder(keyStoreAlias, purposes)
                .setKeySize(keySize)
                .setDigests(*digests)
                .setEncryptionPaddings(*encryptionPaddings)
                .setSignaturePaddings(*signaturePaddings)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(strongBoxBacked)
                    }
                }
                .apply(keyGenParameterSpecBuilder)
                .build()

            generateKey(keyGenParameterSpec)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw mapKeyStoreFailure(
                e = e,
                fallbackMessage = "Failed to generate RSA key in Android Keystore: ${e.message}",
            )
        }
    }

    override fun generateKey(algorithmParameterSpec: AlgorithmParameterSpec): KeyPair {
        return try {
            val keyPairGenerator = keyPairGeneratorFactory()
            keyPairGenerator.initialize(algorithmParameterSpec)
            keyPairGenerator.generateKeyPair()
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw mapKeyStoreFailure(
                e = e,
                fallbackMessage = "Failed to generate RSA key in Android Keystore: ${e.message}",
            )
        }
    }

    override fun getPrivateKey(keyStoreAlias: String): PrivateKey? {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getKey(keyStoreAlias, null) as PrivateKey?
    }

    override fun getPublicKey(keyStoreAlias: String): PublicKey? {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getCertificate(keyStoreAlias)?.publicKey
    }

    override fun isKeyExist(keyStoreAlias: String): Boolean {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.containsAlias(keyStoreAlias)
    }

    override fun deleteKey(keyStoreAlias: String) {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        keyStore.deleteEntry(keyStoreAlias)
    }

    @RequiresApi(Build.VERSION_CODES.P)
    override fun isSupportStrongBox(context: Context): Boolean {
        return context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }

    override fun encrypt(
        publicKey: PublicKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        val oaepSpec = RsaCipherHelper.oaepParameterSpecForPadding(padding)
        return if (oaepSpec != null) {
            encrypt(publicKey, plainText, blockMode, padding, oaepSpec)
        } else {
            encryptWithoutSpec(publicKey, plainText, blockMode, padding)
        }
    }

    override fun encrypt(
        publicKey: PublicKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(RsaTransformation.raw(blockMode, padding))
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, algorithmParameterSpec)
            cipher.doFinal(plainText)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw mapKeyStoreCryptoFailure(
                e = e,
                fallbackMessage = "Failed to encrypt with Android Keystore RSA key: ${e.message}",
            )
        }
    }

    override fun decrypt(
        privateKey: PrivateKey,
        encrypted: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        val oaepSpec = RsaCipherHelper.oaepParameterSpecForPadding(padding)
        return if (oaepSpec != null) {
            decrypt(privateKey, encrypted, blockMode, padding, oaepSpec)
        } else {
            decryptWithoutSpec(privateKey, encrypted, blockMode, padding)
        }
    }

    override fun decrypt(
        privateKey: PrivateKey,
        encrypted: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(RsaTransformation.raw(blockMode, padding))
            cipher.init(Cipher.DECRYPT_MODE, privateKey, algorithmParameterSpec)
            cipher.doFinal(encrypted)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw mapKeyStoreCryptoFailure(
                e = e,
                fallbackMessage = "Failed to decrypt with Android Keystore RSA key: ${e.message}",
            )
        }
    }

    override fun sign(
        privateKey: PrivateKey,
        plainText: ByteArray,
        signatureAlgorithm: String,
    ): ByteArray {
        return try {
            val signer = signatureFactory(signatureAlgorithm)
            signer.initSign(privateKey)
            signer.update(plainText)
            signer.sign()
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw mapKeyStoreCryptoFailure(
                e = e,
                fallbackMessage = "Failed to sign with Android Keystore RSA key: ${e.message}",
            )
        }
    }

    override fun verify(
        publicKey: PublicKey,
        signature: ByteArray,
        plainText: ByteArray,
        signatureAlgorithm: String,
    ): Boolean {
        return try {
            val verifier = signatureFactory(signatureAlgorithm)
            verifier.initVerify(publicKey)
            verifier.update(plainText)
            verifier.verify(signature)
        } catch (e: SignatureException) {
            false
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw mapKeyStoreCryptoFailure(
                e = e,
                fallbackMessage = "Failed to verify Android Keystore RSA signature: ${e.message}",
            )
        }
    }

    private fun encryptWithoutSpec(
        publicKey: PublicKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(RsaTransformation.raw(blockMode, padding))
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            cipher.doFinal(plainText)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw mapKeyStoreCryptoFailure(
                e = e,
                fallbackMessage = "Failed to encrypt with Android Keystore RSA key: ${e.message}",
            )
        }
    }

    private fun decryptWithoutSpec(
        privateKey: PrivateKey,
        encrypted: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray {
        return try {
            val cipher = cipherFactory(RsaTransformation.raw(blockMode, padding))
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            cipher.doFinal(encrypted)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw mapKeyStoreCryptoFailure(
                e = e,
                fallbackMessage = "Failed to decrypt with Android Keystore RSA key: ${e.message}",
            )
        }
    }

    private fun mapKeyStoreFailure(e: Throwable, fallbackMessage: String): CryptoVaultException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException) {
            return CryptoVaultExceptionCodes.strongBoxNotSupported(
                message = "StrongBox is not available on this device",
                cause = e,
            )
        }
        return CryptoVaultExceptionCodes.unknown(
            message = fallbackMessage,
            cause = e,
        )
    }

    private fun mapKeyStoreCryptoFailure(e: Throwable, fallbackMessage: String): CryptoVaultException {
        return when (e) {
            is KeyPermanentlyInvalidatedException -> CryptoVaultExceptionCodes.keyPermanentlyInvalidated(
                message = "Android Keystore key is permanently invalidated and must be regenerated",
                cause = e,
            )
            is UserNotAuthenticatedException -> CryptoVaultExceptionCodes.userNotAuthenticated(
                message = "User must authenticate before using this Android Keystore key",
                cause = e,
            )
            else -> CryptoVaultExceptionCodes.unknown(
                message = fallbackMessage,
                cause = e,
            )
        }
    }
}
