package com.fadlurahmanfdev.example.domain.runner

import android.content.Context
import android.os.Build
import android.util.Base64
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultSecretKeyManager
import com.fadlurahmanfdev.crypto_vault.api.ec.CryptoVaultEC
import com.fadlurahmanfdev.crypto_vault.api.ec.CryptoVaultECAndroidKeyStore
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine

class EcExampleRunner(
    private val cryptoVaultEC: CryptoVaultEC = CryptoVaultEC.create(),
    private val cryptoVaultECAndroidKeyStore: CryptoVaultECAndroidKeyStore =
        CryptoVaultECAndroidKeyStore.create(),
    private val secretKeyManager: CryptoVaultSecretKeyManager = CryptoVaultSecretKeyManager.create(),
) {
    private var privateKeyBytes: ByteArray? = null
    private var publicKeyBytes: ByteArray? = null
    private var signatureBytes: ByteArray? = null

    fun runFullFlow(): ExampleResult {
        val plainText = "Passw0rd!"
        val key = cryptoVaultEC.generateKey()
        val privateKeyBytes = key.private.encoded
        val publicKeyBytes = key.public.encoded
        val encryptedBytes = cryptoVaultEC.encrypt(
            publicKeyBytes = publicKeyBytes,
            plainText = plainText,
        )
        val decryptedText = cryptoVaultEC.decrypt(
            privateKeyBytes = privateKeyBytes,
            encryptedBytes = encryptedBytes,
        )
        val signatureBytes = cryptoVaultEC.generateSignature(
            privateKeyBytes = privateKeyBytes,
            plainText = plainText,
        )
        val isVerified = cryptoVaultEC.verifySignature(
            publicKeyBytes = publicKeyBytes,
            signatureBytes = signatureBytes,
            plainText = plainText,
        )
        val encodedPrivateKey = Base64.encodeToString(privateKeyBytes, Base64.NO_WRAP)
        val encodedPublicKey = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
        val encodedEncryptedText = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        val encodedSignature = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
        return ExampleResult(
            scenarioTitle = "EC full flow (keygen, encrypt, sign)",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("private key", encodedPrivateKey),
                ResultLine("public key", encodedPublicKey),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("decrypted text", decryptedText),
                ResultLine("signature", encodedSignature),
                ResultLine("signature verified", isVerified.toString()),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }

    fun runKeyExchange(context: Context): ExampleResult {
        val bobKeyStoreAlias = "ecdh_example_bob"
        val aliceKeyStoreAlias = "ecdh_example_alice"

        val strongBoxBacked = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            secretKeyManager.isSupportStrongBox(context)
        } else {
            false
        }

        val bobKey = cryptoVaultECAndroidKeyStore.generateKey(
            keyStoreAlias = bobKeyStoreAlias,
            strongBoxBacked = strongBoxBacked,
        )
        val aliceKey = cryptoVaultECAndroidKeyStore.generateKey(
            keyStoreAlias = aliceKeyStoreAlias,
            strongBoxBacked = strongBoxBacked,
        )

        val bobSharedSecretBytes = cryptoVaultECAndroidKeyStore.generateSharedSecret(
            privateKey = bobKey.private,
            otherPublicKey = aliceKey.public,
        )
        val aliceSharedSecretBytes = cryptoVaultECAndroidKeyStore.generateSharedSecret(
            privateKey = aliceKey.private,
            otherPublicKey = bobKey.public,
        )
        val bobDerivedKeyBytes =
            cryptoVaultEC.derivedSharedSecret(sharedSecretBytes = bobSharedSecretBytes)
        val aliceDerivedKeyBytes =
            cryptoVaultEC.derivedSharedSecret(sharedSecretBytes = aliceSharedSecretBytes)

        val encodedBobSharedSecret =
            Base64.encodeToString(bobSharedSecretBytes, Base64.NO_WRAP)
        val encodedAliceSharedSecret =
            Base64.encodeToString(aliceSharedSecretBytes, Base64.NO_WRAP)
        val encodedBobDerivedKey = Base64.encodeToString(bobDerivedKeyBytes, Base64.NO_WRAP)
        val encodedAliceDerivedKey = Base64.encodeToString(aliceDerivedKeyBytes, Base64.NO_WRAP)

        return ExampleResult(
            scenarioTitle = "ECDH key exchange (Alice & Bob)",
            lines = listOf(
                ResultLine("bob shared secret", encodedBobSharedSecret),
                ResultLine("alice shared secret", encodedAliceSharedSecret),
                ResultLine("bob derived key", encodedBobDerivedKey),
                ResultLine("alice derived key", encodedAliceDerivedKey),
                ResultLine(
                    "secrets match",
                    bobSharedSecretBytes.contentEquals(aliceSharedSecretBytes).toString(),
                ),
                ResultLine(
                    "derived keys match",
                    bobDerivedKeyBytes.contentEquals(aliceDerivedKeyBytes).toString(),
                ),
            ),
        )
    }

    fun runGenerateKeystoreKey(): ExampleResult {
        val keystoreAlias = "example_ec"
        val key = cryptoVaultECAndroidKeyStore.generateKey(keyStoreAlias = keystoreAlias)
        val encodedPublicKey = Base64.encodeToString(key.public.encoded, Base64.NO_WRAP)
        return ExampleResult(
            scenarioTitle = "Generate EC key via Android Keystore",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("public key algorithm", key.public.algorithm),
                ResultLine("public key", encodedPublicKey),
            ),
        )
    }

    fun runKeystoreSignVerify(): ExampleResult {
        return ExampleResult(
            scenarioTitle = "EC sign/verify via Android Keystore",
            lines = listOf(
                ResultLine(
                    "note",
                    "Keystore EC private keys are non-exportable. " +
                        "Use the software EC sign/verify examples with raw key bytes.",
                ),
            ),
        )
    }

    fun runGenerateSoftwareKey(): ExampleResult {
        val key = cryptoVaultEC.generateKey()
        privateKeyBytes = key.private.encoded
        publicKeyBytes = key.public.encoded
        signatureBytes = cryptoVaultEC.generateSignature(
            privateKeyBytes = privateKeyBytes!!,
            plainText = "Passw0rd!",
        )
        val encodedPrivateKey = Base64.encodeToString(privateKeyBytes!!, Base64.NO_WRAP)
        val encodedPublicKey = Base64.encodeToString(publicKeyBytes!!, Base64.NO_WRAP)
        val encodedSignature = Base64.encodeToString(signatureBytes!!, Base64.NO_WRAP)
        return ExampleResult(
            scenarioTitle = "Generate EC software key pair",
            lines = listOf(
                ResultLine("private key", encodedPrivateKey),
                ResultLine("public key", encodedPublicKey),
                ResultLine("sample signature", encodedSignature),
                ResultLine("next step", "Run Sign/Verify or Encrypt/Decrypt using this key"),
            ),
        )
    }

    fun runSoftwareSignVerify(): ExampleResult {
        val publicKeyBytes = publicKeyBytes
            ?: return missingKeyResult("Sign & verify with software key")
        val signatureBytes = signatureBytes
            ?: return missingKeyResult("Sign & verify with software key")
        val isVerified = cryptoVaultEC.verifySignature(
            publicKeyBytes = publicKeyBytes,
            plainText = "Passw0rd!",
            signatureBytes = signatureBytes,
        )
        val encodedPublicKey = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
        val encodedSignature = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
        return ExampleResult(
            scenarioTitle = "EC sign/verify with software key",
            lines = listOf(
                ResultLine("public key", encodedPublicKey),
                ResultLine("signature", encodedSignature),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }

    fun runSoftwareEncryptDecrypt(): ExampleResult {
        val privateKeyBytes = privateKeyBytes
            ?: return missingKeyResult("Encrypt & decrypt with software key")
        val publicKeyBytes = publicKeyBytes
            ?: return missingKeyResult("Encrypt & decrypt with software key")
        val plainText = "Passw0rd!"
        val encryptedBytes = cryptoVaultEC.encrypt(
            publicKeyBytes = publicKeyBytes,
            plainText = plainText,
        )
        val decryptedText = cryptoVaultEC.decrypt(
            privateKeyBytes = privateKeyBytes,
            encryptedBytes = encryptedBytes,
        )
        val encodedEncryptedText = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        return ExampleResult(
            scenarioTitle = "EC encrypt/decrypt with software key",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
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
}
