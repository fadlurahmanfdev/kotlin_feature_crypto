package com.fadlurahmanfdev.example.domain.runner

import com.fadlurahmanfdev.crypto_vault.api.ed25519.CryptoVaultED25519
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine

class Ed25519ExampleRunner(
    private val cryptoVaultED25519: CryptoVaultED25519 = CryptoVaultED25519(),
) {

    fun runSignAndVerify(): ExampleResult {
        val plainText = "Passw0rd!Sus4hB9t"
        val key = cryptoVaultED25519.generateKey()
        val signature = cryptoVaultED25519.generateSignature(
            plainText = plainText,
            encodedPrivateKey = key.encodedPrivateKey,
        )
        val isVerified = cryptoVaultED25519.verifySignature(
            plainText = plainText,
            encodedPublicKey = key.encodedPublicKey,
            signature = signature,
        )
        return ExampleResult(
            scenarioTitle = "ED25519 sign and verify",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("private key", key.encodedPrivateKey),
                ResultLine("public key", key.encodedPublicKey),
                ResultLine("signature", signature),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }
}
