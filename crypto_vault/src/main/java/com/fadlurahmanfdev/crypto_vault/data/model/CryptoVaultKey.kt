package com.fadlurahmanfdev.crypto_vault.data.model

data class CryptoVaultKey(
    /**
     * base64 encoded private key
     **/
    val privateKey: String,
    /**
     * base64 encoded public key
     **/
    val publicKey: String
)
