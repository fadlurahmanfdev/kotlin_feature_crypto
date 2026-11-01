package com.fadlurahmanfdev.crypto_vault.internal.ec

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECDHAndroidKeyStoreOperation
import com.fadlurahmanfdev.crypto_vault.domain.contracts.KeyManager
import com.fadlurahmanfdev.crypto_vault.internal.DefaultKeyManager
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement

internal class DefaultECDHAndroidKeyStoreOperation internal constructor(
    private val keyManager: KeyManager,
): ECDHAndroidKeyStoreOperation {
    companion object {
        const val ALGORITHM = KeyProperties.KEY_ALGORITHM_EC
        const val KEY_PROVIDER = "AndroidKeyStore"

        fun create(): ECDHAndroidKeyStoreOperation {
            return DefaultECDHAndroidKeyStoreOperation(
                keyManager = DefaultKeyManager.create()
            )
        }
    }

    override fun getKey(keyStoreAlias: String): KeyPair {
        if (!keyManager.isKeyExist(keyStoreAlias)) {
            throw CryptoVaultExceptionCodes.keyNotFound(
                message = "Android Keystore key was not found for alias \"$keyStoreAlias\"",
            )
        }

        val keyPair = keyManager.getKeyPair(keyStoreAlias)

        if (keyPair.private.algorithm != ALGORITHM) {
            throw CryptoVaultExceptionCodes.keyTypeMismatch(
                message = "Android Keystore key for alias \"$keyStoreAlias\" is " +
                    "\"${keyPair.private.algorithm}\", expected \"$ALGORITHM\"",
            )
        }

        return keyPair
    }

    override fun generateKey(
        keyStoreAlias: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit
    ): KeyPair {
        val purposes =
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_AGREE_KEY
        val parameterSpec = KeyGenParameterSpec.Builder(keyStoreAlias, purposes).apply {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(strongBoxBacked)
            }
        }
            .apply(keyGenParameterSpecBuilder)
            .build()

        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, KEY_PROVIDER)
            keyPairGenerator.initialize(parameterSpec)
            return keyPairGenerator.generateKeyPair()
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (e is StrongBoxUnavailableException) {
                    throw CryptoVaultExceptionCodes.strongBoxNotSupported(e.message, e)
                }
            }

            throw CryptoVaultExceptionCodes.unknown(e.message, e)
        }
    }

    override fun generateSharedSecret(
        privateKey: PrivateKey,
        otherPublicKey: PublicKey,
    ): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(otherPublicKey, true)
        return keyAgreement.generateSecret()
    }
}