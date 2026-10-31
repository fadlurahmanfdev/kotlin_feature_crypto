package com.fadlurahmanfdev.crypto_vault.api

import com.fadlurahmanfdev.crypto_vault.domain.contracts.CertificateManager
import com.fadlurahmanfdev.crypto_vault.internal.DefaultCertificateManager
import java.security.cert.Certificate

class CryptoVaultCertificateManager internal constructor(
    private val certificateManager: CertificateManager,
) {
    companion object {
        fun create(): CryptoVaultCertificateManager {
            return CryptoVaultCertificateManager(
                certificateManager = DefaultCertificateManager.create()
            )
        }
    }

    fun getCertificateAlias(certificate: Certificate): String = certificateManager.getCertificateAlias(certificate)

    fun getCertificate(keyStoreAlias: String): Certificate = certificateManager.getCertificate(keyStoreAlias)

    fun getCertificateChain(keyStoreAlias: String): Array<Certificate> = certificateManager.getCertificateChain(keyStoreAlias)
}