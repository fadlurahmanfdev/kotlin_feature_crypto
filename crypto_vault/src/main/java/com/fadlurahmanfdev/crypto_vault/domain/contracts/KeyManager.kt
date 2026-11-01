package com.fadlurahmanfdev.crypto_vault.domain.contracts

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import java.security.KeyPair
import javax.crypto.SecretKey

interface KeyManager {
    @RequiresApi(Build.VERSION_CODES.P)
    fun isSupportStrongBox(context: Context): Boolean
    fun getSecretKey(keyStoreAlias: String): SecretKey
    fun getKeyPair(keyStoreAlias: String): KeyPair
    fun isKeyExist(keyStoreAlias: String): Boolean
    fun deleteKey(keyStoreAlias: String)
}