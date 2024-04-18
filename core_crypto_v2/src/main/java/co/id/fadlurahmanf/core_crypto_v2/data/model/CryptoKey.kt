package co.id.fadlurahmanf.core_crypto_v2.data.model

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
