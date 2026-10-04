package com.fadlurahmanfdev.example.domain.runner

import android.util.Base64
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultAndroidKeyStoreSecretKeyManager
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAESAndroidKeyStore
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.api.enums.aes.CryptoVaultAESTransformation
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine
import javax.crypto.spec.GCMParameterSpec

class AesExampleRunner(
    private val cryptoVaultAES: CryptoVaultAES = CryptoVaultAES.create(),
    private val cryptoVaultAESAndroidKeyStore: CryptoVaultAESAndroidKeyStore = CryptoVaultAESAndroidKeyStore.create(),
    private val secretKeyManager: CryptoVaultAndroidKeyStoreSecretKeyManager = CryptoVaultAndroidKeyStoreSecretKeyManager.create(),
) {
    fun runKeystoreGcmNoPaddingGeneratedIv(): ExampleResult {
        val plainText = "Passw0rd!"
        val keystoreAlias = "example_aes"

        val existingKey = secretKeyManager.getKey(keystoreAlias)

        if (existingKey != null) {
            secretKeyManager.deleteKey(keystoreAlias)
        }

        val secretKey = cryptoVaultAESAndroidKeyStore.generateKey(
            keyStoreAlias = keystoreAlias
        )

        val encryptedData = cryptoVaultAESAndroidKeyStore.encrypt(
            secretKey = secretKey,
            plainText = plainText.toByteArray(),
        )

        val encodedEncryptedText = Base64.encodeToString(encryptedData.text, Base64.NO_WRAP)
        val ivKey = encryptedData.iv
        val encodedIVKey = Base64.encodeToString(ivKey, Base64.NO_WRAP)

        val loadedKey = cryptoVaultAESAndroidKeyStore.getKey(keystoreAlias)

        val decryptedText = String(
            cryptoVaultAESAndroidKeyStore.decrypt(
                secretKey = loadedKey!!,
                transformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
                iv = encryptedData.iv,
                encrypted = encryptedData.text,
            )
        )

        return ExampleResult(
            scenarioTitle = "AES via Android Keystore, GCM Block Mode, No Padding, With Generated IV",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine(
                    "key info",
                    "Not Exportable Via Android KeyStore, ${if (existingKey != null) "Use Existing Secret Key From AndroidKeyStore" else "Use New Secret Key From Android KeyStore"} "
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
        val keystoreAlias = "example_aes"

        val existingKey = secretKeyManager.getKey(keystoreAlias)

        if (existingKey != null) {
            secretKeyManager.deleteKey(keystoreAlias)
        }

        val secretKey = cryptoVaultAESAndroidKeyStore.generateKey(
            keyStoreAlias = keystoreAlias,
            transformation = CryptoVaultAESTransformation.CBC_PKCS7
        )

        val encryptedData = cryptoVaultAESAndroidKeyStore.encrypt(
            transformation = CryptoVaultAESTransformation.CBC_PKCS7,
            secretKey = secretKey,
            plainText = plainText.toByteArray(),
        )

        val loadedKey = cryptoVaultAESAndroidKeyStore.getKey(keystoreAlias)

        val decryptedText = String(
            cryptoVaultAESAndroidKeyStore.decrypt(
                transformation = CryptoVaultAESTransformation.CBC_PKCS7,
                secretKey = loadedKey!!,
                iv = encryptedData.iv,
                encrypted = encryptedData.text,
            )
        )
        val encodedIVKey = Base64.encodeToString(encryptedData.iv, Base64.NO_WRAP)
        val encodedEncryptedText = Base64.encodeToString(encryptedData.text, Base64.NO_WRAP)

        return ExampleResult(
            scenarioTitle = "AES via Android Keystore, CBC Block Mode, PKCS7Padding With Generated IV",
            lines = listOf(
                ResultLine("keystore alias", keystoreAlias),
                ResultLine("key info", "Not Exportable Via Android KeyStore"),
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
        val secretKey = cryptoVaultAES.generateKey()
        val encodedSecretKey = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        val ivParameterSpec = cryptoVaultAES.generateIVParameterSpecKey()
        val encodedIVKey = Base64.encodeToString(ivParameterSpec.iv, Base64.NO_WRAP)

        val decodedSecretKey = Base64.decode(encodedSecretKey, Base64.NO_WRAP)
        val encrypted = cryptoVaultAES.encrypt(
            secretKey = cryptoVaultAES.parseKey(decodedSecretKey),
            transformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
            algorithmParameterSpec = ivParameterSpec,
            plainText = plainText,
        )
        val encodedEncryptedText = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        val decryptedText = cryptoVaultAES.decrypt(
            secretKey = cryptoVaultAES.parseKey(decodedSecretKey),
            transformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
            algorithmParameterSpec = ivParameterSpec,
            encrypted = encrypted,
        )
        return ExampleResult(
            scenarioTitle = "Software AES Key, GCM Block Mode, No Padding With Custom IV Parameter Spec",
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
        val secretKey = cryptoVaultAES.generateKey()
        val encodedSecretKey = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        val gcmParameterSpec = cryptoVaultAES.generateGCMParameterSpecKey()
        val encodedIVKey = Base64.encodeToString(gcmParameterSpec.iv, Base64.NO_WRAP)
        val encrypted = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            transformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
            algorithmParameterSpec = gcmParameterSpec,
            plainText = plainText,
        )
        val encodedEncryptedText = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        val decryptedText = cryptoVaultAES.decrypt(
            secretKey = secretKey,
            transformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
            algorithmParameterSpec = gcmParameterSpec,
            encrypted = encrypted,
        )
        return ExampleResult(
            scenarioTitle = "Software AES Key, GCM Block Mode, No Padding With Custom GCM Parameter Spec",
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
        val secretKey = cryptoVaultAES.generateKey()
        val encodedSecretKey = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        val ivParameterSpec = cryptoVaultAES.generateIVParameterSpecKey()
        val encodedIVKey = Base64.encodeToString(ivParameterSpec.iv, Base64.NO_WRAP)
        val encrypted = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            transformation = CryptoVaultAESTransformation.CBC_PKCS5,
            algorithmParameterSpec = ivParameterSpec,
            plainText = plainText,
        )
        val encodedEncryptedText = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        val decryptedText = cryptoVaultAES.decrypt(
            secretKey = secretKey,
            transformation = CryptoVaultAESTransformation.CBC_PKCS5,
            algorithmParameterSpec = ivParameterSpec,
            encrypted = encrypted,
        )
        return ExampleResult(
            scenarioTitle = "Software AES Key, CBC Block Mode, PKCS5 Custom IV Parameter Spec",
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
        val secretKey = cryptoVaultAES.generateKey()
        val encodedSecretKey = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        val encryptedModel = cryptoVaultAES.encrypt(
            secretKey = secretKey,
            transformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
            plainText = plainText,
        )
        val encodedEncryptedText = Base64.encodeToString(encryptedModel.text, Base64.NO_WRAP)
        val ivKey = encryptedModel.iv
        val encodedIVKey = Base64.encodeToString(ivKey, Base64.NO_WRAP)
        val decryptedText = cryptoVaultAES.decrypt(
            secretKey = secretKey,
            transformation = CryptoVaultAESTransformation.GCM_NO_PADDING,
            algorithmParameterSpec = GCMParameterSpec(
                128,
                ivKey
            ),
            encrypted = encryptedModel.text,
        )
        return ExampleResult(
            scenarioTitle = "Software AES Key, GCM Block Mode, No Padding with Generated IV Parameter Spec",
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
