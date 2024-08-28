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
            "ENCRYPT_DECRYPT_AES" -> {
                viewModel.encryptDecryptAES()
            }

            "ENCRYPT_DECRYPT_RSA" -> {
                viewModel.encryptDecryptRSA()
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