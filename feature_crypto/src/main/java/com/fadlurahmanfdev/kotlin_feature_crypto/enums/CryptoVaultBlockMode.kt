package com.fadlurahmanfdev.kotlin_feature_crypto.enums

enum class CryptoVaultBlockMode(val value: String) {
    CBC("CBC"),
    GCM("GCM"),
    ECB("ECB"),
    CFB("CFB"),
    OFB("OFB"),
    Poly1305("Poly1305"),
}