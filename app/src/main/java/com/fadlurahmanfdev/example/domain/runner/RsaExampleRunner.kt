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
        val plainTextBytes = plainText.toByteArray()
        val keyPair = cryptoVaultRSA.generateKey()
        val encryptedBytes = cryptoVaultRSA.encrypt(
            publicKey = keyPair.public,
            plainTextBytes = plainTextBytes,
        )
        val decrypted = String(
            cryptoVaultRSA.decrypt(
                privateKey = keyPair.private,
                encryptedBytes = encryptedBytes,
            ),
        )
        val signatureBytes = cryptoVaultRSA.sign(
            privateKey = keyPair.private,
            plainTextBytes = plainTextBytes,
        )
        val isVerified = cryptoVaultRSA.verify(
            publicKey = keyPair.public,
            signatureBytes = signatureBytes,
            plainTextBytes = plainTextBytes,
        )
        val encodedPrivateKey = Base64.encodeToString(keyPair.private.encoded, Base64.NO_WRAP)
        val encodedPublicKey = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
        val encodedEncryptedText = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        val encodedSignature = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
        return ExampleResult(
            scenarioTitle = "RSA with software key pair",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("private key", encodedPrivateKey),
                ResultLine("public key", encodedPublicKey),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("decrypted text", decrypted),
                ResultLine("signature", encodedSignature),
                ResultLine("signature verified", isVerified.toString()),
                ResultLine("round-trip success", (plainText == decrypted).toString()),
            ),
        )
    }

    fun runKeystoreEncryptDecrypt(): ExampleResult {
        val plainText = "Passw0rd!"
        val plainTextBytes = plainText.toByteArray()
        val keystoreAlias = "example_rsa"
        cryptoVaultRSAAndroidKeyStore.deleteKey(keystoreAlias)
        val keyPair = getOrCreateKeystoreKeyPair(keystoreAlias)
        val encryptedBytes = cryptoVaultRSAAndroidKeyStore.encrypt(
            publicKey = keyPair.public,
            plainTextBytes = plainTextBytes,
        )
        val decrypted = String(
            cryptoVaultRSAAndroidKeyStore.decrypt(
                privateKey = keyPair.private,
                encryptedBytes = encryptedBytes,
            ),
        )
        val encodedEncryptedText = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        return ExampleResult(
            scenarioTitle = "RSA encrypt/decrypt via Android Keystore",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("decrypted text", decrypted),
                ResultLine("round-trip success", (plainText == decrypted).toString()),
            ),
        )
    }

    fun runKeystoreSignVerify(): ExampleResult {
        val plainText = "Passw0rd!"
        val plainTextBytes = plainText.toByteArray()
        val keystoreAlias = "example_rsa"
        val privateKey = cryptoVaultRSAAndroidKeyStore.getPrivateKey(keystoreAlias)
            ?: error("Run the Keystore encrypt/decrypt example first to create the RSA key.")
        val publicKey = cryptoVaultRSAAndroidKeyStore.getPublicKey(keystoreAlias)
            ?: error("Run the Keystore encrypt/decrypt example first to create the RSA key.")
        val signatureBytes = cryptoVaultRSAAndroidKeyStore.sign(
            privateKey = privateKey,
            plainTextBytes = plainTextBytes,
        )
        val isVerified = cryptoVaultRSAAndroidKeyStore.verify(
            publicKey = publicKey,
            signatureBytes = signatureBytes,
            plainTextBytes = plainTextBytes,
        )
        val encodedSignature = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
        return ExampleResult(
            scenarioTitle = "RSA sign/verify via Android Keystore",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("plain text", plainText),
                ResultLine("signature", encodedSignature),
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
