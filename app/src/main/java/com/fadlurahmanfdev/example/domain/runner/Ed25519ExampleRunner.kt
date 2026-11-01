package com.fadlurahmanfdev.example.domain.runner

import android.util.Base64
import com.fadlurahmanfdev.crypto_vault.api.ed25519.CryptoVaultED25519
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine

class Ed25519ExampleRunner(
    private val cryptoVaultED25519: CryptoVaultED25519 = CryptoVaultED25519.create(),
) {
    fun runSignAndVerify(): ExampleResult {
        val plainText = "Passw0rd!Sus4hB9t"
        val plainTextBytes = plainText.toByteArray()
        val key = cryptoVaultED25519.generateKey()
        val signatureBytes = cryptoVaultED25519.generateSignature(
            privateKeyBytes = key.privateKeyBytes,
            plainTextBytes = plainTextBytes,
        )
        val isVerified = cryptoVaultED25519.verifySignature(
            publicKeyBytes = key.publicKeyBytes,
            plainTextBytes = plainTextBytes,
            signatureBytes = signatureBytes,
        )
        val encodedPrivateKey = Base64.encodeToString(key.privateKeyBytes, Base64.NO_WRAP)
        val encodedPublicKey = Base64.encodeToString(key.publicKeyBytes, Base64.NO_WRAP)
        val encodedSignature = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
        return ExampleResult(
            scenarioTitle = "ED25519 sign and verify",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("private key", encodedPrivateKey),
                ResultLine("public key", encodedPublicKey),
                ResultLine("signature", encodedSignature),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }
}
