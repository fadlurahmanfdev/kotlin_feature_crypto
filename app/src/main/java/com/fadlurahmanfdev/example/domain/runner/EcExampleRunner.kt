package com.fadlurahmanfdev.example.domain.runner

import android.content.Context
import android.util.Base64
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultKeyManager
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.api.ec.CryptoVaultEC
import com.fadlurahmanfdev.crypto_vault.api.ec.CryptoVaultECAndroidKeyStore
import com.fadlurahmanfdev.example.data.ExampleResult
import com.fadlurahmanfdev.example.data.ResultLine

class EcExampleRunner(
    private val cryptoVaultEC: CryptoVaultEC = CryptoVaultEC.create(),
    private val cryptoVaultECAndroidKeyStore: CryptoVaultECAndroidKeyStore =
        CryptoVaultECAndroidKeyStore.create(),
    private val cryptoVaultAES: CryptoVaultAES = CryptoVaultAES.create(),
    private val keyManager: CryptoVaultKeyManager = CryptoVaultKeyManager.create(),
) {
    fun runFullFlow(): ExampleResult {
        val plainText = "Passw0rd!"
        val key = cryptoVaultEC.generateKey()
        val privateKeyBytes = key.private.encoded
        val publicKeyBytes = key.public.encoded

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
        val encodedSignature = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)

        return ExampleResult(
            scenarioTitle = "EC full flow (keygen, encrypt, sign)",
            lines = listOf(
                ResultLine("plain text", plainText),
                ResultLine("private key", encodedPrivateKey),
                ResultLine("public key", encodedPublicKey),
                ResultLine("signature", encodedSignature),
                ResultLine("signature verified", isVerified.toString()),
            ),
        )
    }

    fun runKeyExchange(context: Context): ExampleResult {
        val plainText = "P4ssw0rd!"

        val bobKey = cryptoVaultEC.generateKey()
        val aliceKey = cryptoVaultEC.generateKey()

        val bobSharedSecretBytes = cryptoVaultEC.generateSharedSecret(
            ephemeralPrivateKeyBytes = bobKey.private.encoded,
            recipientPublicKeyBytes = aliceKey.public.encoded,
        )

        val aliceSharedSecretBytes = cryptoVaultEC.generateSharedSecret(
            ephemeralPrivateKeyBytes = aliceKey.private.encoded,
            recipientPublicKeyBytes = bobKey.public.encoded,
        )

        val bobDerivedAESKeyBytes = cryptoVaultEC.deriveAESKey(sharedSecretBytes = bobSharedSecretBytes).encoded
        val aliceDerivedAESKeyBytes = cryptoVaultEC.deriveAESKey(sharedSecretBytes = aliceSharedSecretBytes).encoded

        val encodedBobSharedSecret =
            Base64.encodeToString(bobSharedSecretBytes, Base64.NO_WRAP)
        val encodedAliceSharedSecret =
            Base64.encodeToString(aliceSharedSecretBytes, Base64.NO_WRAP)
        val encodedBobDerivedKey = Base64.encodeToString(bobDerivedAESKeyBytes, Base64.NO_WRAP)
        val encodedAliceDerivedKey = Base64.encodeToString(aliceDerivedAESKeyBytes, Base64.NO_WRAP)

        val bobAESKey = cryptoVaultAES.parseKey(bobDerivedAESKeyBytes)
        val aliceAESKey = cryptoVaultAES.parseKey(aliceDerivedAESKeyBytes)

        val bobEncrypted = cryptoVaultAES.encrypt(secretKey = bobAESKey, plainText = plainText)
        val aliceDecrypted = cryptoVaultAES.decrypt(secretKey = aliceAESKey, encryptedBytes = bobEncrypted.encryptedBytes, ivBytes = bobEncrypted.ivBytes)

        return ExampleResult(
            scenarioTitle = "ECDH key exchange (Alice & Bob)",
            lines = listOf(
                ResultLine("plain text", plainText),
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
                    bobDerivedAESKeyBytes.contentEquals(aliceDerivedAESKeyBytes).toString(),
                ),
                ResultLine(
                    "bob encrypted text",
                    Base64.encodeToString(bobEncrypted.encryptedBytes, Base64.NO_WRAP),
                ),
                ResultLine(
                    "alice decrypted text",
                    String(aliceDecrypted),
                ),
            ),
        )
    }

    fun runKeyExchangeViaKeyStore(context: Context): ExampleResult {
        val bobKeyStoreAlias = "ecdh_example_bob"
        val aliceKeyStoreAlias = "ecdh_example_alice"

        val plainText = "P4ssw0rd!"

        val supportStrongBox = keyManager.isSupportStrongBox(context)

        val bobKey = cryptoVaultECAndroidKeyStore.generateKey(
            keyStoreAlias = bobKeyStoreAlias,
            strongBoxBacked = supportStrongBox
        )
        val aliceKey = cryptoVaultECAndroidKeyStore.generateKey(
            keyStoreAlias = aliceKeyStoreAlias,
            strongBoxBacked = supportStrongBox
        )

        val bobSharedSecretBytes = cryptoVaultECAndroidKeyStore.generateSharedSecret(
            ephemeralPrivateKey = bobKey.private,
            recipientPublicKey = aliceKey.public,
        )

        val aliceSharedSecretBytes = cryptoVaultECAndroidKeyStore.generateSharedSecret(
            ephemeralPrivateKey = aliceKey.private,
            recipientPublicKey = bobKey.public,
        )

        val bobDerivedAESKeyBytes = cryptoVaultECAndroidKeyStore.deriveAESKey(sharedSecretBytes = bobSharedSecretBytes).encoded
        val aliceDerivedAESKeyBytes = cryptoVaultECAndroidKeyStore.deriveAESKey(sharedSecretBytes = aliceSharedSecretBytes).encoded

        val encodedBobSharedSecret =
            Base64.encodeToString(bobSharedSecretBytes, Base64.NO_WRAP)
        val encodedAliceSharedSecret =
            Base64.encodeToString(aliceSharedSecretBytes, Base64.NO_WRAP)
        val encodedBobDerivedKey = Base64.encodeToString(bobDerivedAESKeyBytes, Base64.NO_WRAP)
        val encodedAliceDerivedKey = Base64.encodeToString(aliceDerivedAESKeyBytes, Base64.NO_WRAP)

        val bobAESKey = cryptoVaultAES.parseKey(bobDerivedAESKeyBytes)
        val aliceAESKey = cryptoVaultAES.parseKey(aliceDerivedAESKeyBytes)

        val bobEncrypted = cryptoVaultAES.encrypt(secretKey = bobAESKey, plainText = plainText)
        val aliceDecrypted = cryptoVaultAES.decrypt(secretKey = aliceAESKey, encryptedBytes = bobEncrypted.encryptedBytes, ivBytes = bobEncrypted.ivBytes)

        return ExampleResult(
            scenarioTitle = "ECDH key exchange (Alice & Bob)",
            lines = listOf(
                ResultLine("plain text", plainText),
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
                    bobDerivedAESKeyBytes.contentEquals(aliceDerivedAESKeyBytes).toString(),
                ),
                ResultLine(
                    "bob encrypted text",
                    Base64.encodeToString(bobEncrypted.encryptedBytes, Base64.NO_WRAP),
                ),
                ResultLine(
                    "alice decrypted text",
                    String(aliceDecrypted),
                ),
            ),
        )
    }
}
