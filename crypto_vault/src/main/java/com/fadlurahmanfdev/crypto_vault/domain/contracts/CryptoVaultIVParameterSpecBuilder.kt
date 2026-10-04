package com.fadlurahmanfdev.crypto_vault.domain.contracts

import java.security.spec.AlgorithmParameterSpec

interface CryptoVaultIVParameterSpecBuilder {
    fun generateIV() : ByteArray
    fun create(iv: ByteArray) : AlgorithmParameterSpec
}