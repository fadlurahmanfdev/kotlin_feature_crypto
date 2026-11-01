package com.fadlurahmanfdev.crypto_vault.domain.contracts

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec

/**
 * Internal contract for software RSA key lifecycle, cipher, and signature operations.
 */
interface RSASoftwareOperation {
    fun generateKey(keySize: Int): KeyPair

    fun parsePublicKey(key: ByteArray): PublicKey

    fun parsePrivateKey(key: ByteArray): PrivateKey

    fun encrypt(
        publicKey: PublicKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray

    fun encrypt(
        publicKey: PublicKey,
        plainText: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray

    fun decrypt(
        privateKey: PrivateKey,
        encrypted: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray

    fun decrypt(
        privateKey: PrivateKey,
        encrypted: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray

    fun sign(
        privateKey: PrivateKey,
        plainText: ByteArray,
        signatureAlgorithm: String,
    ): ByteArray

    fun verify(
        publicKey: PublicKey,
        signature: ByteArray,
        plainText: ByteArray,
        signatureAlgorithm: String,
    ): Boolean
}
