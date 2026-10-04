package com.fadlurahmanfdev.crypto_vault.domain.contracts

import android.security.keystore.KeyGenParameterSpec
import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESTransformation
import com.fadlurahmanfdev.crypto_vault.domain.models.EncryptedData
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey

interface CryptoVaultAESAndroidKeyStoreOperation {
    fun generateKey(
        keystoreAlias: String,
        purposes: Int,
        transformation: CryptoVaultAESTransformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit = {}
    ): SecretKey

    fun generateKey(algorithmParameterSpec: AlgorithmParameterSpec): SecretKey

    fun encrypt(
        secretKey: SecretKey,
        transformation: CryptoVaultAESTransformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
        plainText: String,
    ): EncryptedData

    fun decrypt(
        secretKey: SecretKey,
        transformation: CryptoVaultAESTransformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
        encrypted: ByteArray,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): String
}