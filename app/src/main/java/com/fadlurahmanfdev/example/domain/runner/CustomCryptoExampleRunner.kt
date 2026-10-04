package com.fadlurahmanfdev.example.domain.runner

import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultCustomAsymmetricVault
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultCustomKeyVault
import com.fadlurahmanfdev.crypto_vault.api.enums.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.core.enum.CryptoVaultBlockMode
import com.fadlurahmanfdev.crypto_vault.core.enum.CryptoVaultPadding
import com.fadlurahmanfdev.crypto_vault.core.enum.CryptoVaultSignatureAlgorithm
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine
import java.security.SecureRandom
import javax.crypto.spec.IvParameterSpec

class CustomSymmetricExampleRunner(
    private val cryptoVaultCustomSymmetric: CryptoVaultCustomKeyVault = CryptoVaultCustomKeyVault(),
) {

    fun runChaCha20Poly1305(): ExampleResult {
        val plainText = "P4ssw0rd!Sus4h!B9t"
        val transformation = "${CryptoVaultAlgorithm.ChaCha20}/${CryptoVaultBlockMode.Poly1305}/${CryptoVaultPadding.NoPadding}"
        if (!cryptoVaultCustomSymmetric.isSupported(transformation = transformation)) {
            return ExampleResult(
                scenarioTitle = "ChaCha20-Poly1305 custom symmetric",
                lines = listOf(
                    ResultLine("supported", "false"),
                    ResultLine("transformation", transformation),
                ),
            )
        }
        val key = cryptoVaultCustomSymmetric.generateKey(CryptoVaultAlgorithm.ChaCha20)
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        val ivKey = cryptoVaultCustomSymmetric.encode(nonce)
        val encryptedText = cryptoVaultCustomSymmetric.encrypt(
            algorithm = CryptoVaultAlgorithm.ChaCha20,
            encodedSecretKey = key,
            transformation = transformation,
            plainText = plainText,
            algorithmParameterSpec = IvParameterSpec(cryptoVaultCustomSymmetric.decode(ivKey)),
        )
        val decryptedText = cryptoVaultCustomSymmetric.decrypt(
            algorithm = CryptoVaultAlgorithm.ChaCha20,
            encodedSecretKey = key,
            transformation = transformation,
            algorithmParameterSpec = IvParameterSpec(cryptoVaultCustomSymmetric.decode(ivKey)),
            encryptedText = encryptedText,
        )
        return ExampleResult(
            scenarioTitle = "ChaCha20-Poly1305 custom symmetric",
            lines = listOf(
                ResultLine("transformation", transformation),
                ResultLine("plain text", plainText),
                ResultLine("key", key),
                ResultLine("nonce (IV)", ivKey),
                ResultLine("encrypted text", encryptedText),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }
}

class CustomAsymmetricExampleRunner(
    private val cryptoVaultCustomAsymmetric: CryptoVaultCustomAsymmetricVault = CryptoVaultCustomAsymmetricVault(),
) {

    fun runRsaEncryptSign(): ExampleResult {
        val plainText = "P4ssword!Sus4h"
        val transformation = "${CryptoVaultAlgorithm.RSA}/${CryptoVaultBlockMode.ECB}/${CryptoVaultPadding.OAEPWithSHAAndMGF1Padding}"
        if (!cryptoVaultCustomAsymmetric.isSupported(transformation = transformation)) {
            return ExampleResult(
                scenarioTitle = "Custom asymmetric RSA vault",
                lines = listOf(
                    ResultLine("supported", "false"),
                    ResultLine("transformation", transformation),
                ),
            )
        }
        val key = cryptoVaultCustomAsymmetric.generateKey(CryptoVaultAlgorithm.RSA, 2048)
        val signature = cryptoVaultCustomAsymmetric.generateSignature(
            encodedPrivateKey = key.privateKey,
            plainText = plainText,
            algorithm = CryptoVaultAlgorithm.RSA,
            signatureAlgorithm = CryptoVaultSignatureAlgorithm.SHA256withRSA,
        )
        val isVerified = cryptoVaultCustomAsymmetric.verifySignature(
            encodedPublicKey = key.publicKey,
            algorithm = CryptoVaultAlgorithm.RSA,
            plainText = plainText,
            signature = signature,
            signatureAlgorithm = CryptoVaultSignatureAlgorithm.SHA256withRSA,
        )
        val encryptedText = cryptoVaultCustomAsymmetric.encrypt(
            algorithm = CryptoVaultAlgorithm.RSA,
            blockMode = CryptoVaultBlockMode.ECB,
            padding = CryptoVaultPadding.OAEPWithSHAAndMGF1Padding,
            encodedPublicKey = key.publicKey,
            plainText = plainText,
        )
        val decryptedText = cryptoVaultCustomAsymmetric.decrypt(
            algorithm = CryptoVaultAlgorithm.RSA,
            blockMode = CryptoVaultBlockMode.ECB,
            padding = CryptoVaultPadding.OAEPWithSHAAndMGF1Padding,
            encodedPrivateKey = key.privateKey,
            encryptedText = encryptedText,
        )
        return ExampleResult(
            scenarioTitle = "Custom asymmetric RSA vault",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("private key", key.privateKey),
                ResultLine("public key", key.publicKey),
                ResultLine("signature", signature),
                ResultLine("signature verified", isVerified.toString()),
                ResultLine("encrypted text", encryptedText),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }
}
