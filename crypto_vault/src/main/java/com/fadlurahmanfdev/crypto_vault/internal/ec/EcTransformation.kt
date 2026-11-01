package com.fadlurahmanfdev.crypto_vault.internal.ec

/**
 * Shared EC constants for P-256 keygen, HKDF domain separation, and ECIES envelope layout.
 *
 * Envelope: `[4-byte big-endian eph pub length][eph pub][12-byte IV][ciphertext+tag]`.
 */
internal object EcTransformation {
    const val CURVE_NAME = "secp256r1"
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    const val KEY_AGREEMENT_ALGORITHM = "ECDH"
    const val DEFAULT_HKDF_INFO = "CryptoVaultEC-AES-256-GCM"
    const val AES_KEY_SIZE_BYTES = 32
    const val GCM_IV_SIZE_BYTES = 12
    const val EPH_PUBLIC_KEY_LENGTH_BYTES = 4

    fun defaultHkdfInfoBytes(): ByteArray = DEFAULT_HKDF_INFO.toByteArray(Charsets.UTF_8)
}
