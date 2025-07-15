package com.fadlurahmanfdev.crypto_vault

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.constant.CryptoVaultExceptionConstant
import com.fadlurahmanfdev.crypto_vault.base.BaseKeyCryptoVault
import com.fadlurahmanfdev.crypto_vault.data.model.CryptoVaultEncryptedModel
import com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESEncryptionPadding
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

class CryptoVaultAES : BaseKeyCryptoVault() {
    private val algorithm = com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm.AES

    /**
     * Generate AES Key from android keystore.
     *
     * @param keystoreAlias Key identifier.
     * @param strongBoxBacked Sets whether this key should be protected by a StrongBox security chip.
     * @param blockMode Block mode of aes mode
     * @param encryptionPadding Padding will be added into an encryption text.
     *
     * @throws [CryptoVaultExceptionConstant.STRONG_BOX_NOT_SUPPORTED] if strong box backed not supported.
     * */
    @RequiresApi(Build.VERSION_CODES.M)
    fun generateKeyFromAndroidKeyStore(
        keystoreAlias: String,
        strongBoxBacked: Boolean,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode,
        encryptionPadding: CryptoVaultAESEncryptionPadding,
    ): SecretKey {
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setBlockModes(blockMode.value)
            setEncryptionPaddings(encryptionPadding.value)
            setKeySize(256)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(strongBoxBacked)
            }

        }.build()
        return generateKeyFromAndroidKeyStore(
            algorithm = com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm.AES,
            keyGenParameterSpec = keyGenParameterSpec
        )
    }

    /**
     * Generate AES Key Non Android KeyStore.
     *
     * @return [String] encoded AES key.
     * */
    fun generateKey(): String = generateKey(com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultAlgorithm.AES)

    /**
     * Generate IV Key.
     *
     * @return [String] encoded IV Key.
     * */
    fun generateIVParameterSpecKey(): String {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(16)
        secureRandom.nextBytes(ivBytes)
        val ivParameterSpec = IvParameterSpec(ivBytes)
        return encode(ivParameterSpec.iv)
    }

    /**
     * Generate IV GCM Key.
     *
     * @return [String] encoded IV GCM Key.
     */
    fun generateIVGCMParameterSpecKey(): String {
        val secureRandom = SecureRandom()
        val ivBytes = ByteArray(12)
        secureRandom.nextBytes(ivBytes)
        val ivParameterSpec = GCMParameterSpec(128, ivBytes)
        return encode(ivParameterSpec.iv)
    }

    /**
     * Encrypt plain text using AES Algorithm & Secret key from Android Keystore
     *
     * @param secretKey Secret key get from [generateKeyFromAndroidKeyStore]
     * @param blockMode AES block mode.
     * @param padding AES encryption padding.
     * @param algorithmParameterSpec parameter spec will be used (IV or IV GCM).
     * @param plainText plain text want to be encrypted.
     *
     * */
    fun encrypt(
        secretKey: SecretKey,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        algorithmParameterSpec: AlgorithmParameterSpec,
        plainText: String,
    ): String {
        val transformation = "${algorithm.name}/${blockMode.value}/${padding.value}"
        return encrypt(
            secretKey = secretKey,
            transformation = transformation,
            plainText = plainText,
            algorithmParameterSpec = algorithmParameterSpec
        )
    }

    /**
     * Encrypt plain text using AES Algorithm & Secret key from Android Keystore
     *
     * IV will be generated from cipher
     *
     * @param secretKey Secret key get from [generateKeyFromAndroidKeyStore].
     * @param blockMode AES block mode.
     * @param padding AES encryption padding.
     * @param plainText text want to be encrypted.
     *
     * */
    fun encrypt(
        secretKey: SecretKey,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        plainText: String,
    ): CryptoVaultEncryptedModel {
        val transformation = "${algorithm.name}/${blockMode.value}/${padding.value}"
        return encrypt(
            secretKey = secretKey,
            transformation = transformation,
            plainText = plainText,
        )
    }

    /**
     * Encrypt plain text using encoded secret key & AES algorithm.
     *
     * @param encodedSecretKey encoded secret key.
     * @param blockMode AES block mode.
     * @param padding AES encryption padding.
     * @param algorithmParameterSpec algorithm parameter spec will be used (IV or IV GCM).
     * @param plainText plain text want to be encrypted.
     * */
    fun encrypt(
        encodedSecretKey: String,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        algorithmParameterSpec: AlgorithmParameterSpec,
        plainText: String,
    ): String {
        val transformation = "${algorithm.name}/${blockMode.value}/${padding.value}"
        return encrypt(
            algorithm = algorithm,
            encodedSecretKey = encodedSecretKey,
            transformation = transformation,
            plainText = plainText,
            algorithmParameterSpec = algorithmParameterSpec

        )
    }

    /**
     * Encrypt plain text using Secret key from Android Keystore.
     *
     * IV will be generated from cipher.
     *
     * @param encodedSecretKey encoded secret key.
     * @param blockMode AES block mode.
     * @param padding AES encryption padding.
     * @param plainText text want to be encrypted.
     *
     * */
    fun encrypt(
        encodedSecretKey: String,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        plainText: String,
    ): CryptoVaultEncryptedModel {
        val transformation = "${algorithm.name}/${blockMode.value}/${padding.value}"
        return encrypt(
            algorithm = algorithm,
            encodedSecretKey = encodedSecretKey,
            transformation = transformation,
            plainText = plainText
        )
    }

    /**
     * Decrypt encrypted text using Secret key from Android Keystore.
     *
     * @param secretKey secret key from Android Keystore.
     * @param blockMode AES block mode.
     * @param padding AES encryption padding.
     * @param algorithmParameterSpec iv/gcm that used for decrypt.
     * @param encryptedText encrypted text want to be decrypt.
     *
     * */
    fun decrypt(
        secretKey: SecretKey,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encryptedText: String,
    ): String {
        val transformation = "${algorithm.name}/${blockMode.value}/${padding.value}"
        return decrypt(
            secretKey = secretKey,
            transformation = transformation,
            encryptedText = encryptedText,
            algorithmParameterSpec = algorithmParameterSpec,
        )
    }

    /**
     * Decrypt encrypted text using Secret key from Android Keystore.
     *
     * @param encodedSecretKey encoded secret key.
     * @param blockMode AES block mode.
     * @param padding AES encryption padding.
     * @param algorithmParameterSpec iv/gcm that used for decrypt.
     * @param encryptedText encrypted text want to be decrypt.
     *
     * */
    fun decrypt(
        encodedSecretKey: String,
        blockMode: com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode,
        padding: CryptoVaultAESEncryptionPadding,
        algorithmParameterSpec: AlgorithmParameterSpec,
        encryptedText: String,
    ): String {
        val transformation = "${algorithm.name}/${blockMode.value}/${padding.value}"
        return decrypt(
            algorithm = algorithm,
            transformation = transformation,
            encodedSecretKey = encodedSecretKey,
            algorithmParameterSpec = algorithmParameterSpec,
            encryptedText = encryptedText,
        )
    }
}