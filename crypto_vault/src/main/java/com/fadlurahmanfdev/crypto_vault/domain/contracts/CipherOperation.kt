package com.fadlurahmanfdev.crypto_vault.domain.contracts

import javax.crypto.Cipher

interface CipherOperation {
    fun create(transformation: String): Cipher
}