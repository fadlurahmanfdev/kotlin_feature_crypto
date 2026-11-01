package com.fadlurahmanfdev.crypto_vault.domain.contracts

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.model.EncryptedData
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey

/**
 * Internal contract for Android Keystore AES key lifecycle and cipher operations.
 */
interface AESAndroidKeyStoreOperation {
    fun generateKey(
        keyStoreAlias: String,
        keySize: Int,
        blockMode: String,
        padding: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit,
    ): SecretKey

    fun generateKey(algorithmParameterSpec: AlgorithmParameterSpec): SecretKey

    fun getKey(keyStoreAlias: String): SecretKey?

    fun isKeyExist(keyStoreAlias: String): Boolean

    fun deleteKey(keyStoreAlias: String)

    @RequiresApi(Build.VERSION_CODES.P)
    fun isSupportStrongBox(context: Context): Boolean

    fun encrypt(
        secretKey: SecretKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
    ): EncryptedData

    fun decrypt(
        secretKey: SecretKey,
        encrypted: ByteArray,
        iv: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray
}
