package com.fadlurahmanfdev.kotlin_feature_crypto.core.enums

enum class FeatureCryptoPadding(val value: String) {
    NoPadding("NoPadding"),
    PKCS1Padding("PKCS1Padding"),
    PKCS5Padding("PKCS5Padding"),
    OAEPWithSHAAndMGF1Padding("OAEPWithSHA-1AndMGF1Padding"),
    OAEPWithSHA256AndMGF1Padding("OAEPWithSHA-256AndMGF1Padding")
}