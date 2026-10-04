package com.fadlurahmanfdev.example.domain.runner

import android.os.Build
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultEC
import com.fadlurahmanfdev.crypto_vault.core.enum.ec.CryptoVaultECSignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.core.enum.ec.CryptoVaultECTransformation
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine

class EcExampleRunner(
    private val cryptoVaultEC: CryptoVaultEC = CryptoVaultEC(),
) {
    var encodedPrivateKey: String? = null
        private set
    var encodedPublicKey: String? = null
        private set
    private var signatureText: String? = null
    private var signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA

    fun runFullFlow(): ExampleResult {
        val plainText = "Passw0rd!"
        val key = cryptoVaultEC.generateKey()
        val transformation = CryptoVaultECTransformation.ECDH_AES_GCM
        val encryptedText = cryptoVaultEC.encrypt(
            encodedPublicKey = key.publicKey,
            transformation = transformation,
            plainText = plainText,
        )
        val decryptedText = cryptoVaultEC.decrypt(
            encodedPrivateKey = key.privateKey,
            transformation = transformation,
            encryptedText = encryptedText,
        )
        val signature = cryptoVaultEC.generateSignature(
            encodedPrivateKey = key.privateKey,
            plainText = plainText,
            signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
        )
        val isVerified = cryptoVaultEC.verifySignature(
            encodedPublicKey = key.publicKey,
            signature = signature,
            plainText = plainText,
            signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
        )
        return ExampleResult(
            scenarioTitle = "EC full flow (keygen, encrypt, sign)",
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

    fun runKeyExchange(): ExampleResult {
        val bobKey = cryptoVaultEC.generateKey()
        val aliceKey = cryptoVaultEC.generateKey()
        val bobSharedSecret = cryptoVaultEC.generateSharedSecret(
            ourEncodedPrivateKey = bobKey.privateKey,
            otherEncodedPublicKey = aliceKey.publicKey,
        )
        val aliceSharedSecret = cryptoVaultEC.generateSharedSecret(
            ourEncodedPrivateKey = aliceKey.privateKey,
            otherEncodedPublicKey = bobKey.publicKey,
        )
        val bobDerivedKey = cryptoVaultEC.derivedSharedSecret(sharedSecret = bobSharedSecret)
        val aliceDerivedKey = cryptoVaultEC.derivedSharedSecret(sharedSecret = aliceSharedSecret)
        return ExampleResult(
            scenarioTitle = "ECDH key exchange (Alice & Bob)",
            lines = listOf(
                ResultLine("bob private key", bobKey.privateKey),
                ResultLine("bob public key", bobKey.publicKey),
                ResultLine("alice private key", aliceKey.privateKey),
                ResultLine("alice public key", aliceKey.publicKey),
                ResultLine("bob shared secret", bobSharedSecret),
                ResultLine("alice shared secret", aliceSharedSecret),
                ResultLine("bob derived key", bobDerivedKey),
                ResultLine("alice derived key", aliceDerivedKey),
                ResultLine("secrets match", (bobSharedSecret == aliceSharedSecret).toString()),
                ResultLine("derived keys match", (bobDerivedKey == aliceDerivedKey).toString()),
            ),
        )
    }

    fun runGenerateKeystoreKey(): ExampleResult {
        requireApiM()
        val keystoreAlias = "example_ec"
        val (privateKey, publicKey) = getOrCreateKeystoreKeyPair(keystoreAlias)
        val signature = cryptoVaultEC.generateSignature(
            privateKey = privateKey,
            signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
            plainText = "Passw0rd!",
        )
        return ExampleResult(
            scenarioTitle = "Generate EC key via Android Keystore",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("public key algorithm", publicKey.algorithm),
                ResultLine("sample signature", signature),
            ),
        )
    }

    fun runKeystoreSignVerify(): ExampleResult {
        requireApiM()
        val keystoreAlias = "example_ec"
        val (privateKey, publicKey) = getOrCreateKeystoreKeyPair(keystoreAlias)
        val plainText = "Passw0rd!"
        val signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA
        val signature = cryptoVaultEC.generateSignature(
            privateKey = privateKey,
            signatureAlgorithm = signatureAlgorithm,
            plainText = plainText,
        )
        val isVerified = cryptoVaultEC.verifySignature(
            publicKey = publicKey,
            plainText = plainText,
            signature = signature,
            signatureAlgorithm = signatureAlgorithm,
        )
        return ExampleResult(
            scenarioTitle = "EC sign/verify via Android Keystore",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("plain text", plainText),
                ResultLine("signature", signature),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }

    fun runGenerateSoftwareKey(): ExampleResult {
        val key = cryptoVaultEC.generateKey()
        encodedPrivateKey = key.privateKey
        encodedPublicKey = key.publicKey
        signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA
        signatureText = cryptoVaultEC.generateSignature(
            encodedPrivateKey = key.privateKey,
            signatureAlgorithm = signatureAlgorithm,
            plainText = "Passw0rd!",
        )
        return ExampleResult(
            scenarioTitle = "Generate EC software key pair",
            lines = listOf(
                ResultLine("private key", key.privateKey),
                ResultLine("public key", key.publicKey),
                ResultLine("sample signature", signatureText.orEmpty()),
                ResultLine("next step", "Run Sign/Verify or Encrypt/Decrypt using this key"),
            ),
        )
    }

    fun runSoftwareSignVerify(): ExampleResult {
        val publicKey = encodedPublicKey
            ?: return missingKeyResult("Sign & verify with software key")
        val signature = signatureText
            ?: return missingKeyResult("Sign & verify with software key")
        val isVerified = cryptoVaultEC.verifySignature(
            encodedPublicKey = publicKey,
            plainText = "Passw0rd!",
            signature = signature,
            signatureAlgorithm = signatureAlgorithm,
        )
        return ExampleResult(
            scenarioTitle = "EC sign/verify with software key",
            lines = listOf(
                ResultLine("public key", publicKey),
                ResultLine("signature", signature),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }

    fun runSoftwareEncryptDecrypt(): ExampleResult {
        val privateKey = encodedPrivateKey
            ?: return missingKeyResult("Encrypt & decrypt with software key")
        val publicKey = encodedPublicKey
            ?: return missingKeyResult("Encrypt & decrypt with software key")
        val plainText = "Passw0rd!"
        val transformation = CryptoVaultECTransformation.ECDH_AES_GCM
        val encryptedText = cryptoVaultEC.encrypt(
            encodedPublicKey = publicKey,
            transformation = transformation,
            plainText = plainText,
        )
        val decryptedText = cryptoVaultEC.decrypt(
            encodedPrivateKey = privateKey,
            transformation = transformation,
            encryptedText = encryptedText,
        )
        return ExampleResult(
            scenarioTitle = "EC encrypt/decrypt with software key",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encryptedText),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }

    private fun getOrCreateKeystoreKeyPair(keystoreAlias: String): Pair<java.security.PrivateKey, java.security.PublicKey> {
        val existingPrivate = cryptoVaultEC.getPrivateKeyAndroidKeyStore(keystoreAlias = keystoreAlias)
        val existingPublic = cryptoVaultEC.getPublicAndroidKeyStore(keystoreAlias = keystoreAlias)
        if (existingPrivate != null && existingPublic != null) {
            return existingPrivate to existingPublic
        }
        val key = cryptoVaultEC.generateKeyFromAndroidKeyStore(
            keystoreAlias = keystoreAlias,
            strongBoxBacked = false,
        )
        return key.private to key.public
    }

    private fun missingKeyResult(title: String) = ExampleResult(
        scenarioTitle = title,
        lines = listOf(
            ResultLine(
                label = "error",
                value = "Generate the EC software key pair example first.",
            ),
        ),
    )

    private fun requireApiM() {
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            "Android Keystore EC examples require API 23+"
        }
    }
}
