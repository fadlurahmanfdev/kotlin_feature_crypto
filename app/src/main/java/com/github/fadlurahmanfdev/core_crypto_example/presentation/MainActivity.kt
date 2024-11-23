package com.github.fadlurahmanfdev.core_crypto_example.presentation

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoAESRepositoryImpl
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoED25519RepositoryImpl
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CryptoRSARepositoryImpl
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CustomCryptoAsymmetricRepositoryImpl
import com.fadlurahmanfdev.kotlin_core_crypto.data.repositories.CustomCryptoSymmetricRepositoryImpl
import com.github.fadlurahmanfdev.core_crypto_example.R
import com.github.fadlurahmanfdev.core_crypto_example.data.FeatureModel
import com.github.fadlurahmanfdev.core_crypto_example.domain.ExampleCryptoUseCaseImpl

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
            title = "Verify RSA Signature",
            desc = "Verify RSA Signature",
            enum = "VERIFY_ED25519_SIGNATURE"
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
                cryptoAESRepository = CryptoAESRepositoryImpl(),
                cryptoED25519Repository = CryptoED25519RepositoryImpl(),
                cryptoRSARepository = CryptoRSARepositoryImpl(),
                customSymmetricRepository = CustomCryptoSymmetricRepositoryImpl(),
                customAsymmetricRepository = CustomCryptoAsymmetricRepositoryImpl(),
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

            "VERIFY_ED25519_SIGNATURE" -> {
                viewModel.verifyED25519Signature()
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