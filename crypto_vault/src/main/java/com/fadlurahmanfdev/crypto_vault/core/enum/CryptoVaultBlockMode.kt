package com.fadlurahmanfdev.crypto_vault.core.enum

/**
 * Block modes used when building custom cipher transformations.
 *
 * @property value JCA block mode segment used in `Algorithm/BlockMode/Padding` strings.
 */
enum class CryptoVaultBlockMode(val value: String) {
    CBC("CBC"),
    GCM("GCM"),
    ECB("ECB"),
    CFB("CFB"),
    OFB("OFB"),
    Poly1305("Poly1305"),
}
