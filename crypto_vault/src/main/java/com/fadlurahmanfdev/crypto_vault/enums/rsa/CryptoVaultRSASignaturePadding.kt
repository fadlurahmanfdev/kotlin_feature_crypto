package com.fadlurahmanfdev.crypto_vault.enums.rsa

enum class CryptoVaultRSASignaturePadding(val value:String) {
    RSA_PKCS1("PKCS1"),
    // not available in AndroidKeyStore
    RSA_PSS("PSS")
}