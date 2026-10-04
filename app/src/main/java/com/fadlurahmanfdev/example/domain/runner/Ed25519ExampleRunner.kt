package com.fadlurahmanfdev.example.domain.runner

import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultED25519
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
            encodedPrivateKey = key.privateKey,
        )
        val isVerified = cryptoVaultED25519.verifySignature(
            plainText = plainText,
            encodedPublicKey = key.publicKey,
            signature = signature,
        )
        return ExampleResult(
            scenarioTitle = "ED25519 sign and verify",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("private key", key.privateKey),
                ResultLine("public key", key.publicKey),
                ResultLine("signature", signature),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }
}
