package com.fadlurahmanfdev.kotlin_core_crypto.data.enums

enum class FeatureCryptoBlockMode(val value: String) {
    CBC("CBC"),
    GCM("GCM"),
    ECB("ECB"),
    CFB("CFB"),
    OFB("OFB"),
    Poly1305("Poly1305"),
}