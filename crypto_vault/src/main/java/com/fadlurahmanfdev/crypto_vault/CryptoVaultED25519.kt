package com.fadlurahmanfdev.crypto_vault

import android.util.Log
import com.fadlurahmanfdev.crypto_vault.base.BaseCryptoVault
import com.fadlurahmanfdev.crypto_vault.enums.CryptoVaultSignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.data.model.CryptoVaultKey
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

class CryptoVaultED25519 : BaseCryptoVault() {
    /**
     * Generate Asymmetric Crypto Key
     *
     * @return encoded key (private & public)
     *
     * @return [CryptoVaultKey] ]encoded key (private & public)
     * */
    fun generateKey(): CryptoVaultKey {
        val secureRandom = SecureRandom()
        val keyPairGenerator = Ed25519KeyPairGenerator()
        keyPairGenerator.init(Ed25519KeyGenerationParameters(secureRandom))
        val key = keyPairGenerator.generateKeyPair()
        val privateKey = key.private as Ed25519PrivateKeyParameters
        val publicKey = key.public as Ed25519PublicKeyParameters
        val privateKeyEncoded = encode(privateKey.encoded)
        val publicKeyEncoded = encode(publicKey.encoded)
        return CryptoVaultKey(privateKeyEncoded, publicKeyEncoded)
    }

    /**
     * Generate Signature
     *
     * @param encodedPrivateKey encoded private key
     * @param plainText text want to be convert into signature
     *
     * @return encoded signature
     *
     * @see generateKey
     * @see CryptoVaultSignatureAlgorithm
     * */
    fun generateSignature(
        encodedPrivateKey: String,
        plainText: String
    ): String {
        val nativeKey = Ed25519PrivateKeyParameters(decode(encodedPrivateKey), 0)
        val signer = Ed25519Signer()
        signer.init(true, nativeKey)
        signer.update(plainText.toByteArray(), 0, plainText.length)
        val signature = signer.generateSignature()
        return encode(signature)
    }

    /**
     * Verify the signature
     *
     * @param encodedPublicKey encoded public key
     * @param signature signature want to be verified
     * @param plainText text want to be verified
     *
     * @return [Boolean] is plain text verified with the given signature
     *
     * @see generateKey
     * @see generateSignature
     * @see CryptoVaultSignatureAlgorithm
     * */
    fun verifySignature(
        encodedPublicKey: String,
        plainText: String,
        signature: String,
    ): Boolean {
        return try {
            val nativeKey = Ed25519PublicKeyParameters(decode(encodedPublicKey), 0)
            val verifierDerived = Ed25519Signer()
            verifierDerived.init(false, nativeKey)
            val message = plainText.toByteArray()
            verifierDerived.update(message, 0, plainText.length)
            verifierDerived.verifySignature(decode(signature))
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed verifySignature: ${e.message}")
            false
        }
    }
}