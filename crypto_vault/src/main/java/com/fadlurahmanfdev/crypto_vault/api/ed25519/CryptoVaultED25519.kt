package com.fadlurahmanfdev.crypto_vault.api.ed25519

import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import com.fadlurahmanfdev.crypto_vault.domain.contracts.ED25519Operation
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKeyPair
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
 * Key material, plaintext, and signatures are raw [ByteArray] values (no Base64 inside the vault).
 */
open class CryptoVaultED25519 : ED25519Operation {
    companion object {
        /** Creates a [CryptoVaultED25519] with the default BouncyCastle-backed implementation. */
        fun create(): CryptoVaultED25519 = CryptoVaultED25519()
    }

    /**
     * Generates an ED25519 key pair.
     *
     * @return Raw private and public key bytes.
     * @throws CryptoVaultException with code `UNKNOWN` when generation fails.
     */
    override fun generateKey(): CryptoVaultKeyPair {
        return try {
            val secureRandom = SecureRandom()
            val keyPairGenerator = Ed25519KeyPairGenerator()
            keyPairGenerator.init(Ed25519KeyGenerationParameters(secureRandom))
            val key = keyPairGenerator.generateKeyPair()
            val privateKey = key.private as Ed25519PrivateKeyParameters
            val publicKey = key.public as Ed25519PublicKeyParameters
            CryptoVaultKeyPair(
                encodedPrivateKey = privateKey.encoded,
                encodedPublicKey = publicKey.encoded,
            )
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to generate ED25519 key pair: ${e.message}",
                cause = e,
            )
        }
    }

    /**
     * Signs [plainText] with the given private key bytes.
     *
     * @param encodedPrivateKey Raw ED25519 private key from [generateKey].
     * @param plainText Data to sign.
     * @return Signature bytes.
     * @throws CryptoVaultException with code `UNKNOWN` when signing fails.
     */
    override fun generateSignature(
        encodedPrivateKey: ByteArray,
        plainText: ByteArray,
    ): ByteArray {
        return try {
            val nativeKey = Ed25519PrivateKeyParameters(encodedPrivateKey, 0)
            val signer = Ed25519Signer()
            signer.init(true, nativeKey)
            signer.update(plainText, 0, plainText.size)
            signer.generateSignature()
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to sign with ED25519 private key: ${e.message}",
                cause = e,
            )
        }
    }

    /**
     * Verifies [signature] for [plainText] with the given public key bytes.
     *
     * Returns `false` when the signature does not match. Unexpected setup failures throw
     * [CryptoVaultException].
     *
     * @param encodedPublicKey Matching ED25519 public key.
     * @param plainText Original data that was signed.
     * @param signature Signature bytes from [generateSignature].
     * @return `true` when the signature is valid.
     * @throws CryptoVaultException with code `UNKNOWN` when verification cannot be set up.
     */
    override fun verifySignature(
        encodedPublicKey: ByteArray,
        plainText: ByteArray,
        signature: ByteArray,
    ): Boolean {
        return try {
            val nativeKey = Ed25519PublicKeyParameters(encodedPublicKey, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, nativeKey)
            verifier.update(plainText, 0, plainText.size)
            verifier.verifySignature(signature)
        } catch (e: CryptoVaultException) {
            throw e
        } catch (e: IllegalArgumentException) {
            false
        } catch (e: Throwable) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "Failed to verify ED25519 signature: ${e.message}",
                cause = e,
            )
        }
    }
}
