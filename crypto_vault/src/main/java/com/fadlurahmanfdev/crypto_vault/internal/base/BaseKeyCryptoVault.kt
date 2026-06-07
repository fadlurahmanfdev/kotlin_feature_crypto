package com.fadlurahmanfdev.crypto_vault.internal.base

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.internal.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultEncryptedModel
import java.security.KeyStore
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

abstract class BaseKeyCryptoVault : BaseCryptoVault() {
    open fun generateKey(algorithm: CryptoVaultAlgorithm): String {
        val key = KeyGenerator.getInstance(algorithm.name)
        return encode(key.generateKey().encoded)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    open fun generateKeyFromAndroidKeyStore(
        algorithm: CryptoVaultAlgorithm,
        keyGenParameterSpec: KeyGenParameterSpec,
    ): SecretKey {
        try {
            val keyGenerator = KeyGenerator.getInstance(algorithm.name, "AndroidKeyStore")
            keyGenerator.init(keyGenParameterSpec)
            return keyGenerator.generateKey()
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException) {
                throw CryptoVaultExceptionCodes.strongBoxNotSupported(e.message, e)
            }
            throw CryptoVaultExceptionCodes.unknown(e.message, e)
        }
    }

    open fun getKeyFromAndroidKeyStore(keystoreAlias: String): SecretKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(keystoreAlias, null) as SecretKey?
    }

    open fun encrypt(
        secretKey: SecretKey,
        transformation: String,
        plainText: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    open fun encrypt(
        secretKey: SecretKey,
        transformation: String,
        plainText: String,
    ): CryptoVaultEncryptedModel {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedText = encode(cipher.doFinal(plainText.toByteArray()))
        val ivKey = encode(cipher.iv)
        return CryptoVaultEncryptedModel(
            encryptedText = encryptedText,
            ivKey = ivKey,
        )
    }

    open fun encrypt(
        algorithm: CryptoVaultAlgorithm,
        encodedSecretKey: String,
        transformation: String,
        plainText: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): String {
        val secretKey = SecretKeySpec(decode(encodedSecretKey), algorithm.name)
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec)
        return encode(cipher.doFinal(plainText.toByteArray()))
    }

    open fun encrypt(
        algorithm: CryptoVaultAlgorithm,
        encodedSecretKey: String,
        transformation: String,
        plainText: String,
    ): CryptoVaultEncryptedModel {
        val secretKey = SecretKeySpec(decode(encodedSecretKey), algorithm.name)
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedText = encode(cipher.doFinal(plainText.toByteArray()))
        val ivKey = encode(cipher.iv)
        return CryptoVaultEncryptedModel(
            encryptedText = encryptedText,
            ivKey = ivKey,
        )
    }

    open fun decrypt(
        secretKey: SecretKey,
        transformation: String,
        encryptedText: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec)
        return String(cipher.doFinal(decode(encryptedText)))
    }

    open fun decrypt(
        algorithm: CryptoVaultAlgorithm,
        transformation: String,
        encodedSecretKey: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encryptedText: String,
    ): String {
        val cipher = Cipher.getInstance(transformation)
        val secretKey = SecretKeySpec(decode(encodedSecretKey), algorithm.name)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec)
        return String(cipher.doFinal(decode(encryptedText)))
    }
}
