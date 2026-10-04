package com.fadlurahmanfdev.example.presentation

import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.domain.runner.RsaExampleRunner

class RSAExampleActivity : AlgorithmExampleActivity() {

    private val runner = RsaExampleRunner()

    override val toolbarTitle: String = "RSA Examples"

    override val features: List<FeatureModel> = listOf(
        FeatureModel(
            featureIcon = R.drawable.ic_scenario_encrypt,
            title = "Software key encrypt/decrypt/sign",
            desc = "Generate an RSA key pair in memory, encrypt data, and verify a signature.",
            enum = "RSA_SIMPLE_KEY",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_rsa,
            title = "Android Keystore encrypt/decrypt",
            desc = "Create or reuse an RSA key in Android Keystore and round-trip encrypt data (API 23+).",
            enum = "RSA_KEYSTORE_ENCRYPT",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_ed25519,
            title = "Android Keystore sign/verify",
            desc = "Sign and verify plaintext using the RSA key stored in Android Keystore.",
            enum = "RSA_KEYSTORE_SIGN",
        ),
    )

    override fun onClicked(item: FeatureModel) {
        val result = when (item.enum) {
            "RSA_SIMPLE_KEY" -> runner.runSimpleKeyEncryptDecryptSignVerify()
            "RSA_KEYSTORE_ENCRYPT" -> runner.runKeystoreEncryptDecrypt()
            "RSA_KEYSTORE_SIGN" -> runner.runKeystoreSignVerify()
            else -> return
        }
        showResult(result)
    }
}
