package com.fadlurahmanfdev.crypto_vault.domain.contracts

import java.security.cert.Certificate

interface CertificateManager {
    fun getCertificateAlias(certificate: Certificate): String

    fun getCertificate(keyStoreAlias: String): Certificate

    fun getCertificateChain(keyStoreAlias: String): Array<Certificate>
}