package com.fadlurahmanfdev.example.domain.runner

import android.util.Base64
import com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSA
import com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSAAndroidKeyStore
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine

class RsaExampleRunner(
    private val cryptoVaultRSA: CryptoVaultRSA = CryptoVaultRSA.create(),
    private val cryptoVaultRSAAndroidKeyStore: CryptoVaultRSAAndroidKeyStore =
        CryptoVaultRSAAndroidKeyStore.create(),
) {

    fun runSimpleKeyEncryptDecryptSignVerify(): ExampleResult {
        val plainText = "Passw0rd!"
        val keyPair = cryptoVaultRSA.generateKey()
        val encrypted = cryptoVaultRSA.encrypt(
            publicKey = keyPair.public,
            plainText = plainText.toByteArray(),
        )
        val decrypted = String(
            cryptoVaultRSA.decrypt(
                privateKey = keyPair.private,
                encrypted = encrypted,
            ),
        )
        val signature = cryptoVaultRSA.sign(
            privateKey = keyPair.private,
            plainText = plainText.toByteArray(),
        )
        val isVerified = cryptoVaultRSA.verify(
            publicKey = keyPair.public,
            signature = signature,
            plainText = plainText.toByteArray(),
        )
        return ExampleResult(
            scenarioTitle = "RSA with software key pair",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine(
                    "private key",
                    Base64.encodeToString(keyPair.private.encoded, Base64.NO_WRAP),
                ),
                ResultLine(
                    "public key",
                    Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP),
                ),
                ResultLine("encrypted text", Base64.encodeToString(encrypted, Base64.NO_WRAP)),
                ResultLine("decrypted text", decrypted),
                ResultLine("signature", Base64.encodeToString(signature, Base64.NO_WRAP)),
                ResultLine("signature verified", isVerified.toString()),
                ResultLine("round-trip success", (plainText == decrypted).toString()),
            ),
        )
    }

    fun runKeystoreEncryptDecrypt(): ExampleResult {
        val plainText = "Passw0rd!"
        val keystoreAlias = "example_rsa"
        cryptoVaultRSAAndroidKeyStore.deleteKey(keystoreAlias)
        val keyPair = getOrCreateKeystoreKeyPair(keystoreAlias)
        val encrypted = cryptoVaultRSAAndroidKeyStore.encrypt(
            publicKey = keyPair.public,
            plainText = plainText.toByteArray(),
        )
        val decrypted = String(
            cryptoVaultRSAAndroidKeyStore.decrypt(
                privateKey = keyPair.private,
                encrypted = encrypted,
            ),
        )
        return ExampleResult(
            scenarioTitle = "RSA encrypt/decrypt via Android Keystore",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", Base64.encodeToString(encrypted, Base64.NO_WRAP)),
                ResultLine("decrypted text", decrypted),
                ResultLine("round-trip success", (plainText == decrypted).toString()),
            ),
        )
    }

    fun runKeystoreSignVerify(): ExampleResult {
        val plainText = "Passw0rd!"
        val keystoreAlias = "example_rsa"
        val privateKey = cryptoVaultRSAAndroidKeyStore.getPrivateKey(keystoreAlias)
            ?: error("Run the Keystore encrypt/decrypt example first to create the RSA key.")
        val publicKey = cryptoVaultRSAAndroidKeyStore.getPublicKey(keystoreAlias)
            ?: error("Run the Keystore encrypt/decrypt example first to create the RSA key.")
        val signature = cryptoVaultRSAAndroidKeyStore.sign(
            privateKey = privateKey,
            plainText = plainText.toByteArray(),
        )
        val isVerified = cryptoVaultRSAAndroidKeyStore.verify(
            publicKey = publicKey,
            signature = signature,
            plainText = plainText.toByteArray(),
        )
        return ExampleResult(
            scenarioTitle = "RSA sign/verify via Android Keystore",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("plain text", plainText),
                ResultLine("signature", Base64.encodeToString(signature, Base64.NO_WRAP)),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }

    private fun getOrCreateKeystoreKeyPair(keystoreAlias: String): java.security.KeyPair {
        val existingPrivate = cryptoVaultRSAAndroidKeyStore.getPrivateKey(keystoreAlias)
        val existingPublic = cryptoVaultRSAAndroidKeyStore.getPublicKey(keystoreAlias)
        if (existingPrivate != null && existingPublic != null) {
            return java.security.KeyPair(existingPublic, existingPrivate)
        }
        return cryptoVaultRSAAndroidKeyStore.generateKey(keyStoreAlias = keystoreAlias)
    }
}
