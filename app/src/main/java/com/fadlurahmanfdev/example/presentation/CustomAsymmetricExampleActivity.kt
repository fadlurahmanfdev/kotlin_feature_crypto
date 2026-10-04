package com.fadlurahmanfdev.example.presentation

import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.domain.runner.CustomAsymmetricExampleRunner

class CustomAsymmetricExampleActivity : AlgorithmExampleActivity() {

    private val runner = CustomAsymmetricExampleRunner()

    override val toolbarTitle: String = "Custom Asymmetric Examples"

    override val features: List<FeatureModel> = listOf(
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_custom_asymmetric,
            title = "RSA encrypt, decrypt, sign, verify",
            desc = "Use the custom asymmetric vault for RSA encryption and SHA256withRSA signatures.",
            enum = "CUSTOM_ASYMMETRIC_RSA",
        ),
    )

    override fun onClicked(item: FeatureModel) {
        if (item.enum == "CUSTOM_ASYMMETRIC_RSA") {
            showResult(runner.runRsaEncryptSign())
        }
    }
}
