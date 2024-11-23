package com.fadlurahmanfdev.kotlin_core_crypto.others

import javax.crypto.Cipher

class CryptoUtils {
    fun isTheCipherCombinationCorrect(algorithm: String): Boolean {
        try {
            Cipher.getInstance(algorithm)
            return true
        } catch (e: Exception) {
            return false
        }
    }
}