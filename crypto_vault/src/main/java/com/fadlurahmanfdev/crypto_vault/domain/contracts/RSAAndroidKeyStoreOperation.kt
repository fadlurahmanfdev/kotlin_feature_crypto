package com.fadlurahmanfdev.crypto_vault.domain.contracts

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import androidx.annotation.RequiresApi
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec

/**
 * Internal contract for Android Keystore RSA key lifecycle, cipher, and signature operations.
 */
interface RSAAndroidKeyStoreOperation {
    fun generateKey(
        keyStoreAlias: String,
        keySize: Int,
        encryptionPaddings: Array<String>,
        signaturePaddings: Array<String>,
        digests: Array<String>,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit,
    ): KeyPair

    fun generateKey(algorithmParameterSpec: AlgorithmParameterSpec): KeyPair

    fun getPrivateKey(keyStoreAlias: String): PrivateKey?

    fun getPublicKey(keyStoreAlias: String): PublicKey?

    fun isKeyExist(keyStoreAlias: String): Boolean

    fun deleteKey(keyStoreAlias: String)

    @RequiresApi(Build.VERSION_CODES.P)
    fun isSupportStrongBox(context: Context): Boolean

    fun encrypt(
        publicKey: PublicKey,
        plainTextBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray

    fun encrypt(
        publicKey: PublicKey,
        plainTextBytes: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray

    fun decrypt(
        privateKey: PrivateKey,
        encryptedBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray

    fun decrypt(
        privateKey: PrivateKey,
        encryptedBytes: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray

    fun sign(
        privateKey: PrivateKey,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): ByteArray

    fun verify(
        publicKey: PublicKey,
        signatureBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): Boolean
}
