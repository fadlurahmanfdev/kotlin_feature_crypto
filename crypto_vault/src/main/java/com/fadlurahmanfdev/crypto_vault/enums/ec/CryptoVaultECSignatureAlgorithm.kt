package com.fadlurahmanfdev.crypto_vault.enums.ec

enum class CryptoVaultECSignatureAlgorithm(val value: String) {
    SHA256withECDSA("SHA256withECDSA"),
    // not available in key generated via AndroidKeyStore
    ECIESwithAESCBC("ECIESwithAES-CBC")
}