package com.fadlurahmanfdev.crypto_vault.domain.contracts

import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESBlockMode
import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESEncryptionPadding
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey

interface CryptoVaultAESSoftwareOperation {
    fun generateKey(keySize: Int = 256): SecretKey

    fun encrypt(
        secretKey: SecretKey,
        blockMode: CryptoVaultAESBlockMode = CryptoVaultAESBlockMode.GCM,
        padding: CryptoVaultAESEncryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
        algorithmParameterSpec: AlgorithmParameterSpec,
        plainText: String,
    ): ByteArray
}