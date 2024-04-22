package com.github.fadlurahmanfdev.library_core_crypto.data.model

data class CryptoKey(
    /**
     * base64 encoded private key
     **/
    val privateKey: String,
    /**
     * base64 encoded public key
     **/
    val publicKey: String
)
