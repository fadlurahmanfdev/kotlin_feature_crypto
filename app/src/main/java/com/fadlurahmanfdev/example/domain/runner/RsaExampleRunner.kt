package com.fadlurahmanfdev.example.domain.runner

import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultRSA
import com.fadlurahmanfdev.crypto_vault.core.enum.rsa.CryptoVaultRSAEncryptionPadding
import com.fadlurahmanfdev.crypto_vault.core.enum.rsa.CryptoVaultRSASignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.core.enum.rsa.CryptoVaultRSASignaturePadding
import com.fadlurahmanfdev.crypto_vault.core.enum.rsa.CryptoVaultRSATransformationMode
import com.fadlurahmanfdev.crypto_vault.core.enum.rsa.CryptoVaultRSATransformationPadding
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine

class RsaExampleRunner(
    private val cryptoVaultRSA: CryptoVaultRSA = CryptoVaultRSA(),
) {

    fun runSimpleKeyEncryptDecryptSignVerify(): ExampleResult {
        val plainText = "Passw0rd!"
        val key = cryptoVaultRSA.generateKey()
        val blockMode = CryptoVaultRSATransformationMode.ECB
        val padding = CryptoVaultRSATransformationPadding.OAEPWithSHAAndMGF1Padding
        val encryptedText = cryptoVaultRSA.encrypt(
            encodedPublicKey = key.publicKey,
            blockMode = blockMode,
            padding = padding,
            plainText = plainText,
        )
        val decryptedText = cryptoVaultRSA.decrypt(
            encodedPrivateKey = key.privateKey,
            blockMode = blockMode,
            padding = padding,
            encryptedText = encryptedText,
        )
        val signatureAlgorithm = CryptoVaultRSASignatureAlgorithm.MD5withRSA
        val signature = cryptoVaultRSA.generateSignature(
            encodedPrivateKey = key.privateKey,
            signatureAlgorithm = signatureAlgorithm,
            plainText = plainText,
        )
        val isVerified = cryptoVaultRSA.verifySignature(
            encodedPublicKey = key.publicKey,
            signatureAlgorithm = signatureAlgorithm,
            signature = signature,
            plainText = plainText,
        )
        return ExampleResult(
            scenarioTitle = "RSA with software key pair",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("private key", key.privateKey),
                ResultLine("public key", key.publicKey),
                ResultLine("encrypted text", encryptedText),
                ResultLine("decrypted text", decryptedText),
                ResultLine("signature", signature),
                ResultLine("signature verified", isVerified.toString()),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }

    fun runKeystoreEncryptDecrypt(): ExampleResult {
        val plainText = "Passw0rd!"
        val keystoreAlias = "example_rsa"
        cryptoVaultRSA.deleteKey(keystoreAlias)
        val (privateKey, publicKey) = getOrCreateKeystoreKeyPair(keystoreAlias)
        val blockMode = CryptoVaultRSATransformationMode.ECB
        val padding = CryptoVaultRSATransformationPadding.PKCS1Padding
        val encryptedText = cryptoVaultRSA.encrypt(
            publicKey = publicKey,
            blockMode = blockMode,
            padding = padding,
            plainText = plainText,
        )
        val decryptedText = cryptoVaultRSA.decrypt(
            privateKey = privateKey,
            blockMode = blockMode,
            padding = padding,
            encryptedText = encryptedText,
        )
        return ExampleResult(
            scenarioTitle = "RSA encrypt/decrypt via Android Keystore",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encryptedText),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }

    fun runKeystoreSignVerify(): ExampleResult {
        val plainText = "Passw0rd!"
        val keystoreAlias = "example_rsa"
        val privateKey = cryptoVaultRSA.getPrivateKeyAndroidKeyStore(keystoreAlias = keystoreAlias)
            ?: error("Run the Keystore encrypt/decrypt example first to create the RSA key.")
        val publicKey = cryptoVaultRSA.getPublicAndroidKeyStore(keystoreAlias = keystoreAlias)
            ?: error("Run the Keystore encrypt/decrypt example first to create the RSA key.")
        val signatureAlgorithm = CryptoVaultRSASignatureAlgorithm.MD5withRSA
        val signature = cryptoVaultRSA.generateSignature(
            privateKey = privateKey,
            signatureAlgorithm = signatureAlgorithm,
            plainText = plainText,
        )
        val isVerified = cryptoVaultRSA.verifySignature(
            publicKey = publicKey,
            signatureAlgorithm = signatureAlgorithm,
            signature = signature,
            plainText = plainText,
        )
        return ExampleResult(
            scenarioTitle = "RSA sign/verify via Android Keystore",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("plain text", plainText),
                ResultLine("signature", signature),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }

    private fun getOrCreateKeystoreKeyPair(keystoreAlias: String): Pair<java.security.PrivateKey, java.security.PublicKey> {
        val existingPrivate = cryptoVaultRSA.getPrivateKeyAndroidKeyStore(keystoreAlias = keystoreAlias)
        val existingPublic = cryptoVaultRSA.getPublicAndroidKeyStore(keystoreAlias = keystoreAlias)
        if (existingPrivate != null && existingPublic != null) {
            return existingPrivate to existingPublic
        }
        val key = cryptoVaultRSA.generateKeyFromAndroidKeyStore(
            keystoreAlias = keystoreAlias,
            encryptionPaddings = arrayOf(CryptoVaultRSAEncryptionPadding.RSA_PKCS1),
            signaturePaddings = arrayOf(CryptoVaultRSASignaturePadding.RSA_PKCS1),
        )
        return key.private to key.public
    }

}
