package com.fadlurahmanfdev.crypto_vault.domain.contracts

import android.security.keystore.KeyGenParameterSpec
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.SecretKey

interface ECDHAndroidKeyStoreOperation {
    fun getKey(keyStoreAlias: String): KeyPair
    fun generateKey(
        keyStoreAlias: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit
    ): KeyPair

    fun generateSharedSecret(
        ephemeralPrivateKey: PrivateKey,
        recipientPublicKey: PublicKey,
    ): ByteArray

    fun deriveAESKey(
        sharedSecretBytes: ByteArray,
        saltBytes: ByteArray,
        infoBytes: ByteArray,
    ): SecretKey
}
