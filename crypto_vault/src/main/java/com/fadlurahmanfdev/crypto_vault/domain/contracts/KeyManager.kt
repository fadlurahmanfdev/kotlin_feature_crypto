package com.fadlurahmanfdev.crypto_vault.domain.contracts

import android.content.Context
import java.security.KeyPair
import javax.crypto.SecretKey

interface KeyManager {
    fun isSupportStrongBox(context: Context): Boolean
    fun getSecretKey(keyStoreAlias: String): SecretKey
    fun getKeyPair(keyStoreAlias: String): KeyPair
    fun isKeyExist(keyStoreAlias: String): Boolean
    fun deleteKey(keyStoreAlias: String)
}