package com.fadlurahmanfdev.kotlin_core_crypto.data.repositories

import android.util.Log
import com.fadlurahmanfdev.kotlin_core_crypto.data.model.CryptoKey
import com.fadlurahmanfdev.kotlin_core_crypto.others.BaseCrypto
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

class CryptoED25519RepositoryImpl : BaseCrypto(), CryptoED25519Repository {
    override fun generateKey(): CryptoKey {
        val secureRandom = SecureRandom()
        val keyPairGenerator = Ed25519KeyPairGenerator()
        keyPairGenerator.init(Ed25519KeyGenerationParameters(secureRandom))
        val key = keyPairGenerator.generateKeyPair()
        val privateKey = key.private as Ed25519PrivateKeyParameters
        val publicKey = key.public as Ed25519PublicKeyParameters

        val privateKeyEncoded = encode(privateKey.encoded)
        val publicKeyEncoded = encode(publicKey.encoded)
        return CryptoKey(privateKeyEncoded, publicKeyEncoded)
    }

    override fun generateSignature(
        privateKey: String,
        plainText: String
    ): String? {
        return try {
            val nativeKey = Ed25519PrivateKeyParameters(decode(privateKey), 0)
            val signer = Ed25519Signer()
            signer.init(true, nativeKey)
            signer.update(plainText.toByteArray(), 0, plainText.length)
            val signature = signer.generateSignature()
            encode(signature)
        } catch (e: Throwable) {
            Log.e(
                CryptoED25519RepositoryImpl::class.java.simpleName,
                "failed generateSignature: ${e.message}"
            )
            null
        }
    }

    override fun verifySignature(
        publicKey: String,
        plainText: String,
        signature: String,
    ): Boolean {
        return try {
            val nativeKey = Ed25519PublicKeyParameters(decode(publicKey), 0)
            val verifierDerived = Ed25519Signer()
            verifierDerived.init(false, nativeKey)
            val message = plainText.toByteArray()
            verifierDerived.update(message, 0, plainText.length)
            verifierDerived.verifySignature(decode(signature))
        } catch (e: Throwable) {
            Log.e(
                CryptoED25519RepositoryImpl::class.java.simpleName,
                "failed verifySignature: ${e.message}"
            )
            false
        }
    }
}