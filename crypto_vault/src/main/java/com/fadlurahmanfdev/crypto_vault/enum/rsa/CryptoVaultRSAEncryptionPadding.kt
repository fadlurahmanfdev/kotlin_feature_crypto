package com.fadlurahmanfdev.crypto_vault.enum.rsa

enum class CryptoVaultRSAEncryptionPadding(val value: String) {
    RSA_PKCS1("PKCS1Padding"),
    RSA_OAEP("OAEPPadding"),
}