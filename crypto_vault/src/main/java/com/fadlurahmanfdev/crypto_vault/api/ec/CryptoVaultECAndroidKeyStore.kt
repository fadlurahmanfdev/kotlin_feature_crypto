package com.fadlurahmanfdev.crypto_vault.api.ec

import android.security.keystore.KeyGenParameterSpec
import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECDHAndroidKeyStoreOperation
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.internal.ec.DefaultECAndroidKeyStoreOperation
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.SecretKey

open class CryptoVaultECAndroidKeyStore internal constructor(
    private val operation: ECDHAndroidKeyStoreOperation,
) {
    companion object {
        fun create() : CryptoVaultECAndroidKeyStore {
            return CryptoVaultECAndroidKeyStore(
                operation = DefaultECAndroidKeyStoreOperation.create()
            )
        }
    }

    /**
     * Loads an EC [KeyPair] from Android Keystore by alias.
     *
     * @throws CryptoVaultException with code `KEY_NOT_FOUND` when the alias does not exist,
     *         or `KEY_TYPE_MISMATCH` when the entry is not an EC key.
     */
    open fun getKey(keyStoreAlias: String): KeyPair = operation.getKey(keyStoreAlias)

    open fun generateKey(
        keyStoreAlias: String,
        strongBoxBacked: Boolean = false,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit = {},
    ): KeyPair = operation.generateKey(
        keyStoreAlias = keyStoreAlias,
        strongBoxBacked = strongBoxBacked,
        keyGenParameterSpecBuilder = keyGenParameterSpecBuilder,
    )

    open fun generateSharedSecret(
        ephemeralPrivateKey: PrivateKey,
        recipientPublicKey: PublicKey,
    ): ByteArray = operation.generateSharedSecret(
        ephemeralPrivateKey = ephemeralPrivateKey,
        recipientPublicKey = recipientPublicKey
    )

    open fun deriveAESKey(sharedSecretBytes: ByteArray): SecretKey =
        operation.deriveAESKey(sharedSecretBytes = sharedSecretBytes)
}