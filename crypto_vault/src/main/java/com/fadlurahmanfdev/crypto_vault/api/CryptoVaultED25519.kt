package com.fadlurahmanfdev.crypto_vault.api

import android.util.Log
import com.fadlurahmanfdev.crypto_vault.internal.base.BaseCryptoVault
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKey
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

/**
 * ED25519 signing vault using BouncyCastle.
 *
 * Keys are generated in software; Android Keystore does not expose ED25519 on all devices.
 */
open class CryptoVaultED25519 : BaseCryptoVault() {
    /** Generates an ED25519 key pair encoded as Base64. */
    open fun generateKey(): CryptoVaultKey {
        val secureRandom = SecureRandom()
        val keyPairGenerator = Ed25519KeyPairGenerator()
        keyPairGenerator.init(Ed25519KeyGenerationParameters(secureRandom))
        val key = keyPairGenerator.generateKeyPair()
        val privateKey = key.private as Ed25519PrivateKeyParameters
        val publicKey = key.public as Ed25519PublicKeyParameters
        return CryptoVaultKey(
            privateKey = encode(privateKey.encoded),
            publicKey = encode(publicKey.encoded),
        )
    }

    /** Signs [plainText] with the given Base64-encoded private key. */
    open fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
    ): String {
        val nativeKey = Ed25519PrivateKeyParameters(decode(encodedPrivateKey), 0)
        val signer = Ed25519Signer()
        signer.init(true, nativeKey)
        signer.update(plainText.toByteArray(), 0, plainText.length)
        return encode(signer.generateSignature())
    }

    /** Verifies an ED25519 signature for [plainText]. Returns false when verification fails. */
    open fun verifySignature(
        encodedPublicKey: String,
        plainText: String,
        signature: String,
    ): Boolean {
        return try {
            val nativeKey = Ed25519PublicKeyParameters(decode(encodedPublicKey), 0)
            val verifier = Ed25519Signer()
            verifier.init(false, nativeKey)
            verifier.update(plainText.toByteArray(), 0, plainText.length)
            verifier.verifySignature(decode(signature))
        } catch (e: Throwable) {
            Log.e(this::class.java.simpleName, "failed verifySignature: ${e.message}")
            false
        }
    }
}
