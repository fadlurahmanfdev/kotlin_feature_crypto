package com.fadlurahmanfdev.example.presentation

import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.domain.runner.Ed25519ExampleRunner

class ED25519ExampleActivity : AlgorithmExampleActivity() {

    private val runner = Ed25519ExampleRunner()

    override val toolbarTitle: String = "ED25519 Examples"

    override val features: List<FeatureModel> = listOf(
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_ed25519,
            title = "Sign and verify message",
            desc = "Generate an ED25519 key pair, sign a message, and verify the signature.",
            enum = "ED25519_SIGN_VERIFY",
        ),
    )

    override fun onClicked(item: FeatureModel) {
        if (item.enum == "ED25519_SIGN_VERIFY") {
            showResult(runner.runSignAndVerify())
        }
    }
}
