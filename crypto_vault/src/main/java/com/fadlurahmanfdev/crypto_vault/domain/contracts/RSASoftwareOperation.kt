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

    fun parsePublicKey(publicKeyBytes: ByteArray): PublicKey

    fun parsePrivateKey(privateKeyBytes: ByteArray): PrivateKey

    fun encrypt(
        publicKey: PublicKey,
        plainTextBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray

    fun encrypt(
        publicKey: PublicKey,
        plainTextBytes: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray

    fun decrypt(
        privateKey: PrivateKey,
        encryptedBytes: ByteArray,
        blockMode: String,
        padding: String,
    ): ByteArray

    fun decrypt(
        privateKey: PrivateKey,
        encryptedBytes: ByteArray,
        blockMode: String,
        padding: String,
        algorithmParameterSpec: AlgorithmParameterSpec,
    ): ByteArray

    fun sign(
        privateKey: PrivateKey,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): ByteArray

    fun verify(
        publicKey: PublicKey,
        signatureBytes: ByteArray,
        plainTextBytes: ByteArray,
        signatureAlgorithm: String,
    ): Boolean
}
