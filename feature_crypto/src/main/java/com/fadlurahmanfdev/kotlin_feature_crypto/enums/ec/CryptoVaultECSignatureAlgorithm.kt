package com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec

enum class CryptoVaultECSignatureAlgorithm(val value: String) {
    SHA256withECDSA("SHA256withECDSA"),
    // not available in key generated via AndroidKeyStore
    ECIESwithAESCBC("ECIESwithAES-CBC")
}