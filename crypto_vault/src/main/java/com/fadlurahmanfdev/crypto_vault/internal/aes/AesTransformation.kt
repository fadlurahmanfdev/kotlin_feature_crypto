package com.fadlurahmanfdev.crypto_vault.internal.aes

/**
 * Builds the JCA transformation string `AES/{blockMode}/{padding}`.
 */
internal object AesTransformation {
    const val ALGORITHM = "AES"
    const val DEFAULT_BLOCK_MODE = "GCM"
    const val BLOCK_MODE_CBC = "CBC"
    const val DEFAULT_PADDING = "NoPadding"
    const val GCM_TAG_LENGTH_BITS = 128
    const val DEFAULT_GCM_IV_SIZE_BYTES = 12
    const val DEFAULT_CBC_IV_SIZE_BYTES = 16
    val SUPPORTED_KEY_SIZES = setOf(128, 256)

    fun raw(blockMode: String, padding: String): String = "$ALGORITHM/$blockMode/$padding"
}
