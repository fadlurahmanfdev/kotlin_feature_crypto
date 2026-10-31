package com.fadlurahmanfdev.crypto_vault.domain.contracts

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import javax.crypto.SecretKey

interface SecretKeyManager {
    @RequiresApi(Build.VERSION_CODES.P)
    fun isSupportStrongBox(context: Context): Boolean
    fun getKey(keyStoreAlias: String): SecretKey
    fun isKeyExist(keyStoreAlias: String): Boolean
    fun deleteKey(keyStoreAlias: String)
}