package co.id.fadlurahmanf.core_crypto_v2.data.repositories

import co.id.fadlurahmanf.core_crypto_v2.data.model.CryptoKey
import co.id.fadlurahmanf.core_crypto_v2.others.BaseCrypto
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom
import java.util.logging.Level
import java.util.logging.Logger

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

    override fun generateSignature(plainText: String, encodedPrivateKey: String): String? {
        return try {
            val privateKey = Ed25519PrivateKeyParameters(decode(encodedPrivateKey), 0)
            val signer = Ed25519Signer()
            signer.init(true, privateKey)
            signer.update(plainText.toByteArray(), 0, plainText.length)
            val signature = signer.generateSignature()
            encode(signature)
        } catch (e: Throwable) {
            Logger.getLogger(CryptoED25519Repository::class.java.simpleName)
                .log(Level.INFO, "failed generateSignature: ${e.message}")
            null
        }
    }

    override fun verifySignature(
        text: String,
        signature: String,
        encodedPublicKey: String
    ): Boolean {
        return try {
            val publicKey = Ed25519PublicKeyParameters(decode(encodedPublicKey), 0)
            val verifierDerived = Ed25519Signer()
            verifierDerived.init(false, publicKey)
            val message = text.toByteArray()
            verifierDerived.update(message, 0, text.length)
            verifierDerived.verifySignature(decode(signature))
        } catch (e: Throwable) {
            Logger.getLogger(CryptoED25519Repository::class.java.simpleName)
                .log(Level.INFO, "failed verifySignature: ${e.message}")
            false
        }
    }
}