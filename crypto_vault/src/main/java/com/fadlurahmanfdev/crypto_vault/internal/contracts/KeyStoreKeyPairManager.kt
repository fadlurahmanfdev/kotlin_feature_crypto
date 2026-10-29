package com.fadlurahmanfdev.crypto_vault.internal.contracts

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import androidx.annotation.RequiresApi
import java.security.KeyPair

internal interface KeyStoreKeyPairManager {

    @RequiresApi(Build.VERSION_CODES.P)
    fun isSupportStrongBox(context: Context): Boolean

    @RequiresApi(Build.VERSION_CODES.M)
    fun generateKey(
        keyStoreAlias: String,
        strongBoxBacked: Boolean,
        keyGenParameterSpecBuilder: KeyGenParameterSpec.Builder.() -> Unit = {},
    ): KeyPair
}