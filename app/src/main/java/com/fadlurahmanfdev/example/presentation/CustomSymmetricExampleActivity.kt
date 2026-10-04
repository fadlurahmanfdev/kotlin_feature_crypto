package com.fadlurahmanfdev.example.presentation

import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.domain.runner.CustomSymmetricExampleRunner

class CustomSymmetricExampleActivity : AlgorithmExampleActivity() {

    private val runner = CustomSymmetricExampleRunner()

    override val toolbarTitle: String = "Custom Symmetric Examples"

    override val features: List<FeatureModel> = listOf(
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_custom_symmetric,
            title = "ChaCha20-Poly1305",
            desc = "Encrypt and decrypt using the custom symmetric vault with a random nonce.",
            enum = "CUSTOM_SYMMETRIC_CHACHA20",
        ),
    )

    override fun onClicked(item: FeatureModel) {
        if (item.enum == "CUSTOM_SYMMETRIC_CHACHA20") {
            showResult(runner.runChaCha20Poly1305())
        }
    }
}
