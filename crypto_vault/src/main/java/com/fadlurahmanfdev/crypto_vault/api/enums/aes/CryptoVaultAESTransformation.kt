package com.fadlurahmanfdev.crypto_vault.api.enums.aes

import com.fadlurahmanfdev.crypto_vault.api.enums.CryptoVaultAlgorithm

fun CryptoVaultAESTransformation.rawTransformation(): String {
    return "${algorithm.value}/${blockMode.value}/${padding.value}"
}

enum class CryptoVaultAESTransformation(
    val algorithm: CryptoVaultAlgorithm = CryptoVaultAlgorithm.AES,
    val blockMode: CryptoVaultAESBlockMode,
    val padding: CryptoVaultAESEncryptionPadding,
) {
    GCM_NO_PADDING(
        blockMode = CryptoVaultAESBlockMode.GCM,
        padding = CryptoVaultAESEncryptionPadding.NoPadding
    ),
    CBC_PKCS7(
        blockMode = CryptoVaultAESBlockMode.CBC,
        padding = CryptoVaultAESEncryptionPadding.PKCS7Padding
    ),
    CBC_PKCS5(
        blockMode = CryptoVaultAESBlockMode.CBC,
        padding = CryptoVaultAESEncryptionPadding.PKCS5Padding
    )
}