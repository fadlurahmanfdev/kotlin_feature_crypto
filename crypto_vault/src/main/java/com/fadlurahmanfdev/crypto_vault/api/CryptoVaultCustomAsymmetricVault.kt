package com.fadlurahmanfdev.crypto_vault.api

import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultBlockMode
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultPadding
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultSignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.internal.base.BaseKeyPairCryptoVault
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKey

/**
 * Generic asymmetric crypto vault for algorithms such as RSA and EC.
 *
 * Extend this class to customize encryption, decryption, and signing behavior.
 */
open class CryptoVaultCustomAsymmetricVault : BaseKeyPairCryptoVault() {
    /** Generates a software key pair for [algorithm] encoded as Base64. */
    override fun generateKey(algorithm: CryptoVaultAlgorithm, keySize: Int?): CryptoVaultKey =
        super.generateKey(algorithm, keySize)

    /** Signs [plainText] using the given encoded private key. */
    override fun generateSignature(
        encodedPrivateKey: String,
        plainText: String,
        algorithm: CryptoVaultAlgorithm,
        signatureAlgorithm: CryptoVaultSignatureAlgorithm,
    ): String = super.generateSignature(
        encodedPrivateKey = encodedPrivateKey,
        plainText = plainText,
        algorithm = algorithm,
        signatureAlgorithm = signatureAlgorithm,
    )

    /** Verifies [signature] for [plainText]. Returns false when verification fails. */
    override fun verifySignature(
        encodedPublicKey: String,
        signature: String,
        plainText: String,
        algorithm: CryptoVaultAlgorithm,
        signatureAlgorithm: CryptoVaultSignatureAlgorithm,
    ): Boolean = super.verifySignature(
        encodedPublicKey = encodedPublicKey,
        signature = signature,
        plainText = plainText,
        algorithm = algorithm,
        signatureAlgorithm = signatureAlgorithm,
    )

    /** Encrypts [plainText] with the given algorithm, block mode, and padding. */
    open fun encrypt(
        algorithm: CryptoVaultAlgorithm,
        blockMode: CryptoVaultBlockMode,
        padding: CryptoVaultPadding,
        encodedPublicKey: String,
        plainText: String,
    ): String = super.encrypt(
        transformation = "${algorithm.name}/${blockMode.value}/${padding.value}",
        algorithm = algorithm,
        encodedPublicKey = encodedPublicKey,
        plainText = plainText,
    )

    /** Decrypts [encryptedText] with the given algorithm, block mode, and padding. */
    open fun decrypt(
        algorithm: CryptoVaultAlgorithm,
        blockMode: CryptoVaultBlockMode,
        padding: CryptoVaultPadding,
        encodedPrivateKey: String,
        encryptedText: String,
    ): String = super.decrypt(
        transformation = "${algorithm.name}/${blockMode.value}/${padding.value}",
        algorithm = algorithm,
        encodedPrivateKey = encodedPrivateKey,
        encryptedText = encryptedText,
    )
}
