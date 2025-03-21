package com.fadlurahmanfdev.example.presentation

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.kotlin_feature_crypto.FeatureCryptoAES
import com.fadlurahmanfdev.kotlin_feature_crypto.FeatureCryptoCustomSymmetric
import com.fadlurahmanfdev.kotlin_feature_crypto.FeatureCryptoED25519
import com.fadlurahmanfdev.kotlin_feature_crypto.FeatureCryptoRSA
import com.fadlurahmanfdev.kotlin_feature_crypto.FeatureCryptoEC
import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.domain.ExampleCryptoUseCaseImpl

class MainActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    lateinit var viewModel: MainViewModel

    private val features: List<FeatureModel> = listOf<FeatureModel>(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encryption Decryption AES",
            desc = "Encryption Decryption using AES",
            enum = "ENCRYPT_DECRYPT_AES"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encryption Decryption RSA",
            desc = "Encryption Decryption using RSA",
            enum = "ENCRYPT_DECRYPT_RSA"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Combine RSA & AES",
            desc = "Combine RSA & AES",
            enum = "COMBINE_RSA_AES"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Example Crypto ED25519",
            desc = "Example Crypto ED25519",
            enum = "EXAMPLE_ED25519"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Example EC Key Exchange",
            desc = "Example EC Key Exchange",
            enum = "EXAMPLE_EC_KEY_EXCHANGE"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Example EC",
            desc = "Example EC",
            enum = "EXAMPLE_EC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Custom Symmetric Crypto",
            desc = "Custom Symmetric Crypto",
            enum = "CUSTOM_SYMMETRIC_CRYPTO"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Custom Asymmetric Crypto",
            desc = "Custom Asymmetric Crypto",
            enum = "CUSTOM_ASYMMETRIC_CRYPTO"
        ),
    )

    private lateinit var rv: RecyclerView

    private lateinit var adapter: ListExampleAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
        rv = findViewById<RecyclerView>(R.id.rv)

        viewModel = MainViewModel(
            exampleCryptoUseCase = ExampleCryptoUseCaseImpl(
                cryptoAESRepository = FeatureCryptoAES(),
                cryptoED25519Repository = FeatureCryptoED25519(),
                cryptoRSARepository = FeatureCryptoRSA(),
                cryptoECRepository = FeatureCryptoEC(),
                featureCryptoCustomSymmetric = FeatureCryptoCustomSymmetric(),
            )
        )

        rv.setItemViewCacheSize(features.size)
        rv.setHasFixedSize(true)

        adapter = ListExampleAdapter()
        adapter.setCallback(this)
        adapter.setList(features)
        adapter.setHasStableIds(true)
        rv.adapter = adapter
    }

    lateinit var eccRepositoryImpl: FeatureCryptoEC


    override fun onClicked(item: FeatureModel) {
        when (item.enum) {
            "ENCRYPT_DECRYPT_AES" -> {
                viewModel.encryptDecryptAES()
            }

            "ENCRYPT_DECRYPT_RSA" -> {
                viewModel.encryptDecryptRSA()
            }

            "COMBINE_RSA_AES" -> {
                viewModel.encryptCombineRSAAndAES()
            }

            "EXAMPLE_ED25519" -> {
                viewModel.exampleED25519()
            }

            "EXAMPLE_EC_KEY_EXCHANGE" -> {
                viewModel.exampleECKeyExchange()
            }

            "EXAMPLE_EC" -> {
                viewModel.exampleEC()
            }

            "CUSTOM_SYMMETRIC_CRYPTO" -> {
                viewModel.customSymmetricCrypto()
            }

            "CUSTOM_ASYMMETRIC_CRYPTO" -> {
                viewModel.customAsymmetricCrypto()
            }
        }
    }
}