package co.id.fadlurahmanf.core_crypto_v2.data.repositories

import co.id.fadlurahmanf.core_crypto_v2.data.enums.RSAMethod
import co.id.fadlurahmanf.core_crypto_v2.data.enums.RSASignatureMethod
import co.id.fadlurahmanf.core_crypto_v2.data.model.CryptoKey

interface CryptoRSARepository {
    fun generateKey(): CryptoKey
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        method: RSASignatureMethod
    ): String?

    fun verifySignature(
        encodedPublicKey: String,
        encodedSignature: String,
        plainText: String,
        method: RSASignatureMethod,
    ): Boolean

    fun encrypt(encodedPublicKey: String, plainText: String, method: RSAMethod): String?
    fun decrypt(encodedPrivateKey: String, encryptedText: String, method: RSAMethod): String?
}