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
            desc = "Alice and Bob derive the same shared secret via ECDH, HKDF, then AES-GCM.",
            enum = "EC_KEY_EXCHANGE",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_ec,
            title = "ECDH key exchange (Keystore)",
            desc = "Alice and Bob ECDH via Android Keystore, then HKDF + AES-GCM.",
            enum = "EC_KEY_EXCHANGE_VIA_KEYSTORE",
        ),
    )

    override fun onClicked(item: FeatureModel) {
        val result = when (item.enum) {
            "EC_FULL_FLOW" -> runner.runFullFlow()
            "EC_KEY_EXCHANGE" -> runner.runKeyExchange(this)
            "EC_KEY_EXCHANGE_VIA_KEYSTORE" -> runner.runKeyExchangeViaKeyStore(this)
            else -> return
        }
        showResult(result)
    }
}
