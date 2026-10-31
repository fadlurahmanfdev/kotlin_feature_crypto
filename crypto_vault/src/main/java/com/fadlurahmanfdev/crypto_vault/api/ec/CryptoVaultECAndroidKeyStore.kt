package com.fadlurahmanfdev.crypto_vault.api.ec

import android.security.keystore.KeyGenParameterSpec
import com.fadlurahmanfdev.crypto_vault.domain.contracts.ECDHAndroidKeyStoreOperation
import com.fadlurahmanfdev.crypto_vault.internal.ec.DefaultECDHAndroidKeyStoreOperation
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

open class CryptoVaultECAndroidKeyStore internal constructor(
    private val operation: ECDHAndroidKeyStoreOperation,
) {
    companion object {
        fun create() : CryptoVaultECAndroidKeyStore {
            return CryptoVaultECAndroidKeyStore(
                operation = DefaultECDHAndroidKeyStoreOperation.create()
            )
        }
    }

    open fun generateKey(
        keyStoreAlias: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit
    ): KeyPair = operation.generateKey(
        keyStoreAlias = keyStoreAlias,
        strongBoxBacked = strongBoxBacked,
        keyGenParameterSpecBuilder = keyGenParameterSpecBuilder,
    )

    open fun generateSharedSecret(
        privateKey: PrivateKey,
        otherPublicKey: PublicKey,
    ): ByteArray = operation.generateSharedSecret(
        privateKey = privateKey,
        otherPublicKey = otherPublicKey
    )
}