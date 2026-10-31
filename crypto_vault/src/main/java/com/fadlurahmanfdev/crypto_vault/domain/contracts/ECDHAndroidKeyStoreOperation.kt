package com.fadlurahmanfdev.crypto_vault.domain.contracts

import android.security.keystore.KeyGenParameterSpec
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

interface ECDHAndroidKeyStoreOperation {
    fun generateKey(
        keyStoreAlias: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit
    ): KeyPair

    fun generateSharedSecret(
        privateKey: PrivateKey,
        otherPublicKey: PublicKey,
    ): ByteArray

}