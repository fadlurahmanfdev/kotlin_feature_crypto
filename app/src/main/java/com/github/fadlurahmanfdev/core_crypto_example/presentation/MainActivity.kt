package com.github.fadlurahmanfdev.core_crypto_example.presentation

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.github.fadlurahmanfdev.core_crypto_example.R
import com.github.fadlurahmanfdev.core_crypto_example.data.FeatureModel
import com.github.fadlurahmanfdev.core_crypto_example.domain.ExampleCryptoUseCaseImpl
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoAESRepositoryImpl
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoED25519RepositoryImpl
import com.github.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoRSARepositoryImpl

class MainActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    lateinit var viewModel: MainViewModel

    private val features: List<FeatureModel> = listOf<FeatureModel>(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "AES KEY",
            desc = "Generate AES Key",
            enum = "GENERATE_AES_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt AES",
            desc = "Encrypt using AES method",
            enum = "ENCRYPT_AES"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Decrypt AES",
            desc = "Decrypt using AES method",
            enum = "DECRYPT_AES"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "RSA KEY",
            desc = "Generate RSA Key",
            enum = "GENERATE_RSA_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt RSA",
            desc = "Encrypt using RSAA method",
            enum = "ENCRYPT_RSA"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Decrypt RSA",
            desc = "Decrypt using RSA method",
            enum = "DECRYPT_RSA"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Generate RSA Signature",
            desc = "Generate RSA Signature",
            enum = "GENERATE_RSA_SIGNATURE"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Verify RSA Signature",
            desc = "Verify RSA Signature",
            enum = "VERIFY_RSA_SIGNATURE"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Generate ED25519 Key",
            desc = "Generate ED25519 Key",
            enum = "GENERATE_ED25519_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Generate ED25519 Signature",
            desc = "Generate ED25519 Signature",
            enum = "GENERATE_ED25519_SIGNATURE"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Verify RSA Signature",
            desc = "Verify RSA Signature",
            enum = "VERIFY_ED25519_SIGNATURE"
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
                cryptoAESRepository = CryptoAESRepositoryImpl(),
                cryptoED25519Repository = CryptoED25519RepositoryImpl(),
                cryptoRSARepository = CryptoRSARepositoryImpl(),
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

    override fun onClicked(item: FeatureModel) {
        when (item.enum) {
            "GENERATE_AES_KEY" -> {
                viewModel.generateAESKey()
            }

            "ENCRYPT_AES" -> {
                viewModel.encryptAES()
            }

            "DECRYPT_AES" -> {
                viewModel.decryptAES()
            }

            "GENERATE_RSA_KEY" -> {
                viewModel.generateRSAKey()
            }

            "ENCRYPT_RSA" -> {
                viewModel.encryptRSA()
            }

            "DECRYPT_RSA" -> {
                viewModel.decryptRSA()
            }

            "GENERATE_RSA_SIGNATURE" -> {
                viewModel.generateRSASignature()
            }

            "VERIFY_RSA_SIGNATURE" -> {
                viewModel.verifyAESSignature()
            }

            "GENERATE_ED25519_KEY" -> {
                viewModel.generateED25519Key()
            }

            "GENERATE_ED25519_SIGNATURE" -> {
                viewModel.generateED25519Signature()
            }

            "VERIFY_ED25519_SIGNATURE" -> {
                viewModel.verifyED25519Signature()
            }
        }
    }
}