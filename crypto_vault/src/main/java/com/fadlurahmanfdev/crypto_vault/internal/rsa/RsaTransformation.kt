package com.fadlurahmanfdev.crypto_vault.internal.rsa

/**
 * Builds the JCA transformation string `RSA/{blockMode}/{padding}`.
 */
internal object RsaTransformation {
    const val ALGORITHM = "RSA"
    const val DEFAULT_BLOCK_MODE = "ECB"
    const val DEFAULT_PADDING = "OAEPWithSHA-256AndMGF1Padding"
    const val DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA"
    const val DEFAULT_KEYSTORE_SIGNATURE_ALGORITHM = "SHA256withRSA/PSS"
    const val DEFAULT_KEY_SIZE = 2048
    const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    const val DEFAULT_KEYSTORE_ENCRYPTION_PADDING = "OAEPPadding"
    const val DEFAULT_KEYSTORE_SIGNATURE_PADDING = "PSS"
    val SUPPORTED_KEY_SIZES = setOf(2048, 3072, 4096)
    val DEFAULT_DIGESTS = arrayOf("SHA-256", "SHA-512")

    fun raw(blockMode: String, padding: String): String = "$ALGORITHM/$blockMode/$padding"

    fun isOaepSha256Padding(padding: String): Boolean {
        return padding.contains("OAEP", ignoreCase = true) &&
            padding.contains("SHA-256", ignoreCase = true)
    }
}
