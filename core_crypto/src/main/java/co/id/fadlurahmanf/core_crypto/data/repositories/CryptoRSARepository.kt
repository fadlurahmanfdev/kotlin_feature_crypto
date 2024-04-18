package co.id.fadlurahmanf.core_crypto.data.repositories

import co.id.fadlurahmanf.core_crypto.data.enums.RSAMethod
import co.id.fadlurahmanf.core_crypto.data.enums.RSASignatureMethod
import co.id.fadlurahmanf.core_crypto.data.model.CryptoKey

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