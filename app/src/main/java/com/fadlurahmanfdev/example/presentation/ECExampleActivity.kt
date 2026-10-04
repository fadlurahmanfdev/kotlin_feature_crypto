package com.fadlurahmanfdev.example.presentation

import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.domain.runner.EcExampleRunner

class ECExampleActivity : AlgorithmExampleActivity() {

    private val runner = EcExampleRunner()

    override val toolbarTitle: String = "EC Examples"

    override val features: List<FeatureModel> = listOf(
        FeatureModel(
            featureIcon = R.drawable.ic_scenario_encrypt,
            title = "Full EC flow",
            desc = "Generate a key pair, encrypt with ECDH+AES-GCM, and sign with ECDSA.",
            enum = "EC_FULL_FLOW",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_ec,
            title = "ECDH key exchange",
            desc = "Alice and Bob derive the same shared secret and derived AES key.",
            enum = "EC_KEY_EXCHANGE",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_ec,
            title = "Generate Android Keystore key",
            desc = "Create or load an EC key pair from Android Keystore (API 23+).",
            enum = "EC_KEYSTORE_GENERATE",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_ed25519,
            title = "Android Keystore sign/verify",
            desc = "Sign and verify using the EC key stored in Android Keystore.",
            enum = "EC_KEYSTORE_SIGN_VERIFY",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_scenario_encrypt,
            title = "Generate software key pair",
            desc = "Generate an in-memory EC key pair for the multi-step software examples below.",
            enum = "EC_SOFTWARE_GENERATE",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_ed25519,
            title = "Software sign/verify",
            desc = "Verify the signature created after generating the software key pair.",
            enum = "EC_SOFTWARE_SIGN_VERIFY",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_scenario_encrypt,
            title = "Software encrypt/decrypt",
            desc = "Encrypt and decrypt using the software key pair from the generate step.",
            enum = "EC_SOFTWARE_ENCRYPT_DECRYPT",
        ),
    )

    override fun onClicked(item: FeatureModel) {
        val result = when (item.enum) {
            "EC_FULL_FLOW" -> runner.runFullFlow()
            "EC_KEY_EXCHANGE" -> runner.runKeyExchange()
            "EC_KEYSTORE_GENERATE" -> runner.runGenerateKeystoreKey()
            "EC_KEYSTORE_SIGN_VERIFY" -> runner.runKeystoreSignVerify()
            "EC_SOFTWARE_GENERATE" -> runner.runGenerateSoftwareKey()
            "EC_SOFTWARE_SIGN_VERIFY" -> runner.runSoftwareSignVerify()
            "EC_SOFTWARE_ENCRYPT_DECRYPT" -> runner.runSoftwareEncryptDecrypt()
            else -> return
        }
        showResult(result)
    }
}
