package com.fadlurahmanfdev.example.domain.runner

import android.util.Base64
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAESAndroidKeyStore
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine

class AesExampleRunner(
    private val cryptoVaultAES: CryptoVaultAES = CryptoVaultAES.create(),
    private val cryptoVaultAESAndroidKeyStore: CryptoVaultAESAndroidKeyStore =
        CryptoVaultAESAndroidKeyStore.create(),
) {
    fun runKeystoreGcmNoPaddingGeneratedIv(): ExampleResult {
        val plainText = "Passw0rd!"
        val plainTextBytes = plainText.toByteArray()
        val keystoreAlias = "example_aes"

        val existingKey = cryptoVaultAESAndroidKeyStore.getKey(keystoreAlias)
        if (existingKey != null) {
            cryptoVaultAESAndroidKeyStore.deleteKey(keystoreAlias)
        }

        val secretKey = cryptoVaultAESAndroidKeyStore.generateKey(
            keyStoreAlias = keystoreAlias,
        )

        val encryptedData = cryptoVaultAESAndroidKeyStore.encrypt(
            secretKey = secretKey,
            plainTextBytes = plainTextBytes,
        )

        val encodedEncryptedText =
            Base64.encodeToString(encryptedData.encryptedBytes, Base64.NO_WRAP)
        val encodedIVKey = Base64.encodeToString(encryptedData.ivBytes, Base64.NO_WRAP)

        val loadedKey = cryptoVaultAESAndroidKeyStore.getKey(keystoreAlias)
        val decryptedText = String(
            cryptoVaultAESAndroidKeyStore.decrypt(
                secretKey = loadedKey!!,
                encryptedBytes = encryptedData.encryptedBytes,
                ivBytes = encryptedData.ivBytes,
            ),
        )

        return ExampleResult(
            scenarioTitle = "AES via Android Keystore, GCM, No Padding, Generated IV",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine(
                    "key info",
                    "Not exportable via Android Keystore. " +
                        if (existingKey != null) {
                            "Replaced existing key."
                        } else {
                            "Created new key."
                        },
                ),
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("generated IV", encodedIVKey),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }

    fun runKeystoreCbcPkcs7GeneratedIv(): ExampleResult {
        val plainText = "Passw0rd!"
        val plainTextBytes = plainText.toByteArray()
        val keystoreAlias = "example_aes_cbc"

        if (cryptoVaultAESAndroidKeyStore.isKeyExist(keystoreAlias)) {
            cryptoVaultAESAndroidKeyStore.deleteKey(keystoreAlias)
        }

        val secretKey = cryptoVaultAESAndroidKeyStore.generateKey(
            keyStoreAlias = keystoreAlias,
            blockMode = "CBC",
            padding = "PKCS7Padding",
        )

        val encryptedData = cryptoVaultAESAndroidKeyStore.encrypt(
            secretKey = secretKey,
            plainTextBytes = plainTextBytes,
            blockMode = "CBC",
            padding = "PKCS7Padding",
        )

        val decryptedText = String(
            cryptoVaultAESAndroidKeyStore.decrypt(
                secretKey = secretKey,
                encryptedBytes = encryptedData.encryptedBytes,
                ivBytes = encryptedData.ivBytes,
                blockMode = "CBC",
                padding = "PKCS7Padding",
            ),
        )
        val encodedIVKey = Base64.encodeToString(encryptedData.ivBytes, Base64.NO_WRAP)
        val encodedEncryptedText =
            Base64.encodeToString(encryptedData.encryptedBytes, Base64.NO_WRAP)

        return ExampleResult(
            scenarioTitle = "AES via Android Keystore, CBC, PKCS7, Generated IV",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("key info", "Not exportable via Android Keystore"),
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("generated IV", encodedIVKey),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }

    fun runGcmNoPaddingCustomIvParameterSpec(): ExampleResult {
        val plainText = "Passw0rd!"
        val plainTextBytes = plainText.toByteArray()
        val secretKey = cryptoVaultAES.generateKey()
        val encodedSecretKey = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        val gcmParameterSpec = cryptoVaultAES.generateGCMParameterSpec()
        val encodedIVKey = Base64.encodeToString(gcmParameterSpec.iv, Base64.NO_WRAP)

        val encryptedBytes = cryptoVaultAES.encrypt(
            secretKey = cryptoVaultAES.parseKey(
                keyBytes = Base64.decode(encodedSecretKey, Base64.NO_WRAP),
            ),
            plainTextBytes = plainTextBytes,
            algorithmParameterSpec = gcmParameterSpec,
        )
        val encodedEncryptedText = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        val decryptedText = String(
            cryptoVaultAES.decrypt(
                secretKey = cryptoVaultAES.parseKey(
                    keyBytes = Base64.decode(encodedSecretKey, Base64.NO_WRAP),
                ),
                encryptedBytes = encryptedBytes,
                algorithmParameterSpec = gcmParameterSpec,
            ),
        )
        return ExampleResult(
            scenarioTitle = "Software AES, GCM, No Padding, Custom GCM Parameter Spec",
            lines = listOf(
                ResultLine("encoded secret key", encodedSecretKey),
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("encoded iv key", encodedIVKey),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }

    fun runGcmNoPaddingCustomGcmParameterSpec(): ExampleResult {
        val plainText = "Passw0rd!"
        val plainTextBytes = plainText.toByteArray()
        val secretKey = cryptoVaultAES.generateKey()
        val encodedSecretKey = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        val gcmParameterSpec = cryptoVaultAES.generateGCMParameterSpec()
        val encodedIVKey = Base64.encodeToString(gcmParameterSpec.iv, Base64.NO_WRAP)
        val encryptedBytes = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            plainTextBytes = plainTextBytes,
            algorithmParameterSpec = gcmParameterSpec,
        )
        val encodedEncryptedText = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        val decryptedText = String(
            cryptoVaultAES.decrypt(
                secretKey = secretKey,
                encryptedBytes = encryptedBytes,
                algorithmParameterSpec = gcmParameterSpec,
            ),
        )
        return ExampleResult(
            scenarioTitle = "Software AES, GCM, No Padding, Custom GCM Parameter Spec (direct key)",
            lines = listOf(
                ResultLine("encoded secret key", encodedSecretKey),
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("encoded iv key", encodedIVKey),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }

    fun runCbcPkcs5CustomIv(): ExampleResult {
        val plainText = "Passw0rd!"
        val plainTextBytes = plainText.toByteArray()
        val secretKey = cryptoVaultAES.generateKey()
        val encodedSecretKey = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        val ivParameterSpec = cryptoVaultAES.generateIvParameterSpec()
        val encodedIVKey = Base64.encodeToString(ivParameterSpec.iv, Base64.NO_WRAP)
        val encryptedBytes = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            plainTextBytes = plainTextBytes,
            blockMode = "CBC",
            padding = "PKCS5Padding",
            algorithmParameterSpec = ivParameterSpec,
        )
        val encodedEncryptedText = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        val decryptedText = String(
            cryptoVaultAES.decrypt(
                secretKey = secretKey,
                encryptedBytes = encryptedBytes,
                blockMode = "CBC",
                padding = "PKCS5Padding",
                algorithmParameterSpec = ivParameterSpec,
            ),
        )
        return ExampleResult(
            scenarioTitle = "Software AES, CBC, PKCS5, Custom IV Parameter Spec",
            lines = listOf(
                ResultLine("encoded secret key", encodedSecretKey),
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("encoded iv key", encodedIVKey),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }

    fun runGcmNoPaddingWithGeneratedIv(): ExampleResult {
        val plainText = "Passw0rd!"
        val plainTextBytes = plainText.toByteArray()
        val secretKey = cryptoVaultAES.generateKey()
        val encodedSecretKey = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        val encryptedModel = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            plainTextBytes = plainTextBytes,
        )
        val encodedEncryptedText =
            Base64.encodeToString(encryptedModel.encryptedBytes, Base64.NO_WRAP)
        val encodedIVKey = Base64.encodeToString(encryptedModel.ivBytes, Base64.NO_WRAP)
        val decryptedText = String(
            cryptoVaultAES.decrypt(
                secretKey = secretKey,
                encryptedBytes = encryptedModel.encryptedBytes,
                ivBytes = encryptedModel.ivBytes,
            ),
        )
        return ExampleResult(
            scenarioTitle = "Software AES, GCM, No Padding, Generated IV",
            lines = listOf(
                ResultLine("encoded secret key", encodedSecretKey),
                ResultLine("plain text", plainText),
                ResultLine("encrypted text", encodedEncryptedText),
                ResultLine("encoded iv key", encodedIVKey),
                ResultLine("decrypted text", decryptedText),
                ResultLine("round-trip success", (plainText == decryptedText).toString()),
            ),
        )
    }
}
