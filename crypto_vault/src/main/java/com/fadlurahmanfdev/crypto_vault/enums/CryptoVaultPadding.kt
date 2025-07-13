package com.fadlurahmanfdev.crypto_vault.enums

enum class CryptoVaultPadding(val value: String) {
    NoPadding("NoPadding"),
    PKCS1Padding("PKCS1Padding"),
    PKCS5Padding("PKCS5Padding"),
    OAEPWithSHAAndMGF1Padding("OAEPWithSHA-1AndMGF1Padding"),
    OAEPWithSHA256AndMGF1Padding("OAEPWithSHA-256AndMGF1Padding")
}