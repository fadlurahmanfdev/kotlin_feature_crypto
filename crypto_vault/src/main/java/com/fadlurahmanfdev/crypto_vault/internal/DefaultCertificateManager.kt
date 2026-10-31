package com.fadlurahmanfdev.crypto_vault.internal

import com.fadlurahmanfdev.crypto_vault.domain.contracts.CertificateManager
import java.security.KeyStore
import java.security.cert.Certificate

class DefaultCertificateManager : CertificateManager {

    companion object {
        fun create() : CertificateManager {
            return DefaultCertificateManager()
        }
    }
    private fun keyStoreInstance() = KeyStore.getInstance("AndroidKeyStore")

    override fun getCertificateAlias(certificate: Certificate): String {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getCertificateAlias(certificate)
    }

    override fun getCertificate(keyStoreAlias: String): Certificate {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getCertificate(keyStoreAlias)
    }

    override fun getCertificateChain(keyStoreAlias: String): Array<Certificate> {
        val keyStore = keyStoreInstance()
        keyStore.load(null)
        return keyStore.getCertificateChain(keyStoreAlias)
    }
}