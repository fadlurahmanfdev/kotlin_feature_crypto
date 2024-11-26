package com.fadlurahmanfdev.kotlin_feature_crypto.data.enums

enum class FeatureCryptoSignatureAlgorithm {
    SHA1withRSA,
    SHA256withRSA,
    SHA512withRSA,
    MD5withRSA,
    SHA1withDSA,
    SHA256withDSA,
    ECDSA,
    Ed25519,
    Ed448,
}