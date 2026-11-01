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
        val signature = cryptoVaultED25519.generateSignature(
            encodedPrivateKey = key.encodedPrivateKey,
            plainText = plainTextBytes,
        )
        val isVerified = cryptoVaultED25519.verifySignature(
            encodedPublicKey = key.encodedPublicKey,
            plainText = plainTextBytes,
            signature = signature,
        )
        return ExampleResult(
            scenarioTitle = "ED25519 sign and verify",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine(
                    "private key",
                    Base64.encodeToString(key.encodedPrivateKey, Base64.NO_WRAP),
                ),
                ResultLine(
                    "public key",
                    Base64.encodeToString(key.encodedPublicKey, Base64.NO_WRAP),
                ),
                ResultLine(
                    "signature",
                    Base64.encodeToString(signature, Base64.NO_WRAP),
                ),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }
}
