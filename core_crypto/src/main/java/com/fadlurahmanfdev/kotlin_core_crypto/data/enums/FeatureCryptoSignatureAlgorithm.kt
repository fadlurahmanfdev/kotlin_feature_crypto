package com.fadlurahmanfdev.kotlin_core_crypto.data.enums

enum class FeatureCryptoSignatureAlgorithm {
    SHA1withRSA,
    SHA256withRSA,
    SHA512withRSA,
    MD5withRSA,
    SHA1withDSA,
    SHA256withDSA,
    SHA256withECDSA,
    SHA512withECDSA,
    Ed25519,
    Ed448,
}