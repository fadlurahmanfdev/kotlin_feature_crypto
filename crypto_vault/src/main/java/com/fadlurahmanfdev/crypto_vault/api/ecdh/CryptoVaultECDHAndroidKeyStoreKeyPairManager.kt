package com.fadlurahmanfdev.crypto_vault.api.ecdh

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.crypto_vault.internal.DefaultECDHAndroidKeyStoreKeyPairManager
import com.fadlurahmanfdev.crypto_vault.internal.contracts.KeyStoreKeyPairManager
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement

class CryptoVaultECDHAndroidKeyStoreKeyPairManager internal constructor(
    private val keyPairManager: KeyStoreKeyPairManager,
) {
    companion object {
        fun create() : CryptoVaultECDHAndroidKeyStoreKeyPairManager {
            return CryptoVaultECDHAndroidKeyStoreKeyPairManager(
                keyPairManager = DefaultECDHAndroidKeyStoreKeyPairManager()
            )
        }
    }

    fun generateKey(
        keyStoreAlias: String,
        strongBoxBacked: Boolean,
    ): KeyPair = keyPairManager.generateKey(
        keyStoreAlias = keyStoreAlias,
        strongBoxBacked = strongBoxBacked
    )

    @RequiresApi(Build.VERSION_CODES.P)
    fun isSupportStrongBox(context: Context): Boolean = keyPairManager.isSupportStrongBox(context)

    fun generateSharedSecret(
        privateKey: PrivateKey,
        otherPublicKey: PublicKey,
    ): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(otherPublicKey, true)
        return keyAgreement.generateSecret()
    }
}
