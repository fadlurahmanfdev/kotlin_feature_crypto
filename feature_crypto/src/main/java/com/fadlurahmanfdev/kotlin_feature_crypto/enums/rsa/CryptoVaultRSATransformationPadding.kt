package com.fadlurahmanfdev.kotlin_feature_crypto.enums.rsa

enum class CryptoVaultRSATransformationPadding(val value: String) {
    PKCS1Padding("PKCS1Padding"),
    OAEPWithSHAAndMGF1Padding("OAEPWithSHA-1AndMGF1Padding"),
    // not available in AndroidKeyStore
    OAEPWithSHA256AndMGF1Padding("OAEPWithSHA-256AndMGF1Padding")
}