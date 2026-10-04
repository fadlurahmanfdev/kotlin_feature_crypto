package com.fadlurahmanfdev.example.data

import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.presentation.AESExampleActivity
import com.fadlurahmanfdev.example.presentation.CustomAsymmetricExampleActivity
import com.fadlurahmanfdev.example.presentation.CustomSymmetricExampleActivity
import com.fadlurahmanfdev.example.presentation.ECExampleActivity
import com.fadlurahmanfdev.example.presentation.ED25519ExampleActivity
import com.fadlurahmanfdev.example.presentation.RSAExampleActivity

enum class AlgorithmCatalog(
    val title: String,
    val subtitle: String,
    val iconRes: Int,
    val activityClass: Class<*>,
) {
    AES(
        title = "AES",
        subtitle = "Symmetric encryption with CBC and GCM block modes",
        iconRes = R.drawable.ic_algorithm_aes,
        activityClass = AESExampleActivity::class.java,
    ),
    RSA(
        title = "RSA",
        subtitle = "Asymmetric encryption, signing, and Android Keystore",
        iconRes = R.drawable.ic_algorithm_rsa,
        activityClass = RSAExampleActivity::class.java,
    ),
    EC(
        title = "Elliptic Curve (EC)",
        subtitle = "ECDH key exchange, ECDSA signing, and ECIES encryption",
        iconRes = R.drawable.ic_algorithm_ec,
        activityClass = ECExampleActivity::class.java,
    ),
    ED25519(
        title = "ED25519",
        subtitle = "Edwards-curve digital signatures",
        iconRes = R.drawable.ic_algorithm_ed25519,
        activityClass = ED25519ExampleActivity::class.java,
    ),
    CUSTOM_SYMMETRIC(
        title = "Custom Symmetric",
        subtitle = "ChaCha20-Poly1305 via custom symmetric vault",
        iconRes = R.drawable.ic_algorithm_custom_symmetric,
        activityClass = CustomSymmetricExampleActivity::class.java,
    ),
    CUSTOM_ASYMMETRIC(
        title = "Custom Asymmetric",
        subtitle = "RSA encrypt/decrypt and sign/verify via custom vault",
        iconRes = R.drawable.ic_algorithm_custom_asymmetric,
        activityClass = CustomAsymmetricExampleActivity::class.java,
    ),
}
