package co.id.fadlurahmanf.core_crypto.data.repositories

import android.util.Log
import co.id.fadlurahmanf.core_crypto.data.enums.RSAMethod
import co.id.fadlurahmanf.core_crypto.data.enums.RSASignatureMethod
import co.id.fadlurahmanf.core_crypto.data.model.CryptoKey
import co.id.fadlurahmanf.core_crypto.others.BaseCrypto
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

class CryptoRSARepositoryImpl : BaseCrypto(), CryptoRSARepository {
    override fun generateKey(): CryptoKey {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048)
        val keyPair = keyGen.generateKeyPair()
        val publicKey = encode(keyPair.public.encoded)
        val privateKey = encode(keyPair.private.encoded)
        return CryptoKey(privateKey = privateKey, publicKey = publicKey)
    }

    override fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        method: RSASignatureMethod,
    ): String? {
        return try {
            val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
            val privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec)
            val signer = Signature.getInstance(getRSASignatureAlgorithmBasedOnFlow(method))
            signer.initSign(privateKey)
            signer.update(plainText.toByteArray())
            encode(signer.sign())
        } catch (e: Throwable) {
            Log.d(
                CryptoRSARepository::class.java.simpleName,
                "failed generateSignature: ${e.message}"
            )
            null
        }
    }

    override fun verifySignature(
        encodedPublicKey: String,
        encodedSignature: String,
        plainText: String,
        method: RSASignatureMethod,
    ): Boolean {
        return try {
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec)
            val signer = Signature.getInstance(getRSASignatureAlgorithmBasedOnFlow(method))
            signer.initVerify(publicKey)
            signer.update(plainText.toByteArray())
            signer.verify(decode(encodedSignature))
            true
        } catch (e: Throwable) {
            Log.d(
                CryptoRSARepository::class.java.simpleName,
                "failed verifySignature: ${e.message}"
            )
            false
        }
    }

    override fun encrypt(encodedPublicKey: String, plainText: String, method: RSAMethod): String? {
        return try {
            val cipher = Cipher.getInstance(getRSATransformationBasedOnFlow(method))
            val publicKeySpec = X509EncodedKeySpec(decode(encodedPublicKey))
            val publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            val encryptedByteArray = cipher.doFinal(plainText.toByteArray())
            encode(encryptedByteArray)
        } catch (e: Throwable) {
            Log.e(CryptoRSARepository::class.java.simpleName, "failed encrypt: ${e.message}")
            null
        }
    }

    override fun decrypt(
        encodedPrivateKey: String,
        encryptedText: String,
        method: RSAMethod
    ): String? {
        return try {
            val cipher = Cipher.getInstance(getRSATransformationBasedOnFlow(method))
            val privateKeySpec = PKCS8EncodedKeySpec(decode(encodedPrivateKey))
            val privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            String(cipher.doFinal(decode(encryptedText)))
        } catch (e: Throwable) {
            Log.e(CryptoRSARepository::class.java.simpleName, "failed decrypt: ${e.message}")
            null
        }
    }
}