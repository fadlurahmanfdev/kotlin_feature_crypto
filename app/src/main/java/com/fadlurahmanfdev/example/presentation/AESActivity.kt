package com.fadlurahmanfdev.example.presentation

import android.os.Bundle
import android.util.Log
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
import com.fadlurahmanfdev.kotlin_feature_crypto.CryptoVaultAES
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    lateinit var viewModel: MainViewModel
    lateinit var cryptoVaultAES: CryptoVaultAES

    lateinit var encryptedText: String
    lateinit var ivKey: String

    private val features: List<FeatureModel> = listOf<FeatureModel>(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Simple Key With Custom IV Key",
            desc = "Encrypt & Decrypt AES Simple Key With Custom IV Key & Without AndroidKeyStore",
            enum = "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_WITH_CUSTOM_IV_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Simple Key With Custom IV GCM Key",
            desc = "Encrypt & Decrypt AES Simple Key With Custom IV GCM Key & Without AndroidKeyStore",
            enum = "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_WITH_CUSTOM_IV_GCM_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Simple Key With IV GCM Key \uD83D\uDC4D \uD83D\uDC4D \uD83D\uDC4D",
            desc = "Encrypt & Decrypt AES Simple Key With IV GCM Key & Without AndroidKeyStore",
            enum = "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_WITH_IV_GCM_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Via Android KeyStore With Generated IV \uD83D\uDC4D \uD83D\uDC4D \uD83D\uDC4D",
            desc = "Encrypt & Decrypt AES Via AES Key generated from Android KeyStore With Generated IV",
            enum = "ENCRYPT_DECRYPT_AES_KEYSTORE_WITH_GENERATED_IV"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Via Android KeyStore With Custom IV",
            desc = "Encrypt & Decrypt AES Via AES Key generated from Android KeyStore With Custom IV",
            enum = "ENCRYPT_DECRYPT_AES_KEYSTORE_WITH_CUSTOM_IV"
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

        cryptoVaultAES = CryptoVaultAES()

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
            "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_WITH_CUSTOM_IV_KEY" -> {
                val secretKey = cryptoVaultAES.generateKey()
                val encodedSecretKey = cryptoVaultAES.encode(secretKey.encoded)
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% secret key: $encodedSecretKey"
                )

                ivKey = cryptoVaultAES.generateIVParameterSpecKey(16)
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% iv spec key: $ivKey"
                )

                encryptedText =
                    cryptoVaultAES.encrypt(
                        secretKey,
                        IvParameterSpec(cryptoVaultAES.decode(ivKey)),
                        "Passw0rd!"
                    )

                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )

                val decryptedText = cryptoVaultAES.decrypt(
                    secretKey = SecretKeySpec(cryptoVaultAES.decode(encodedSecretKey), "AES"),
                    algorithmParameterSpec = GCMParameterSpec(128, cryptoVaultAES.decode(ivKey)),
                    encryptedText = encryptedText
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )
            }

            "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_WITH_CUSTOM_IV_GCM_KEY" -> {
                val secretKey = cryptoVaultAES.generateKey()
                val encodedSecretKey = cryptoVaultAES.encode(secretKey.encoded)
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% secret key: $encodedSecretKey"
                )

                ivKey = cryptoVaultAES.generateIVGCMParameterSpecKey(12)
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% iv gvm spec key: $ivKey"
                )

                encryptedText =
                    cryptoVaultAES.encrypt(
                        secretKey,
                        GCMParameterSpec(128, cryptoVaultAES.decode(ivKey)),
                        "Passw0rd!"
                    )

                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )

                val decryptedText = cryptoVaultAES.decrypt(
                    secretKey = SecretKeySpec(cryptoVaultAES.decode(encodedSecretKey), "AES"),
                    parameterSpec = ivKey,
                    encryptedText = encryptedText
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )
            }

            "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_WITH_IV_GCM_KEY" -> {
                val secretKey = cryptoVaultAES.generateKey()
                val encodedSecretKey = cryptoVaultAES.encode(secretKey.encoded)
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% secret key: $encodedSecretKey"
                )

                val encryptedModel =
                    cryptoVaultAES.encrypt(
                        secretKey,
                        "Passw0rd!"
                    )
                encryptedText = encryptedModel.encryptedText
                ivKey = encryptedModel.ivKey

                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% iv key: $ivKey"
                )

                val decryptedText = cryptoVaultAES.decrypt(
                    secretKey = SecretKeySpec(cryptoVaultAES.decode(encodedSecretKey), "AES"),
                    algorithmParameterSpec = IvParameterSpec(cryptoVaultAES.decode(ivKey)),
                    encryptedText = encryptedText
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )
            }

            "ENCRYPT_DECRYPT_AES_KEYSTORE_WITH_GENERATED_IV" -> {
                val isStrongBoxBackedSupported =
                    cryptoVaultAES.isStrongBoxBackedSupported("example_aes")
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% is strong box backed supported: $isStrongBoxBackedSupported"
                )
                var secretKeyFromAndroidKeyStore =
                    cryptoVaultAES.getKeyFromAndroidKeyStore(keystoreAlias = "example_aes")
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% is secret key from AndroidKeyStore exist: ${secretKeyFromAndroidKeyStore != null}"
                )

                if (secretKeyFromAndroidKeyStore == null) {
                    secretKeyFromAndroidKeyStore = cryptoVaultAES.generateKey(
                        "example_aes",
                        strongBoxBacked = isStrongBoxBackedSupported
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% successfully generate secret key from AndroidKeyStore"
                    )
                }

                val encryptedModel =
                    cryptoVaultAES.encrypt(secretKeyFromAndroidKeyStore, plainText = "Passw0rd!")
                encryptedText = encryptedModel.encryptedText
                ivKey = encryptedModel.ivKey
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% iv key: $ivKey"
                )

                val decryptedText = cryptoVaultAES.decrypt(
                    secretKeyFromAndroidKeyStore,
                    encryptedText = encryptedText,
                    parameterSpec = ivKey
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decryptedText text: $decryptedText"
                )
            }

            "ENCRYPT_DECRYPT_AES_KEYSTORE_WITH_CUSTOM_IV" -> {
                val isStrongBoxBackedSupported =
                    cryptoVaultAES.isStrongBoxBackedSupported("example_aes_2")
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% is strong box backed supported: $isStrongBoxBackedSupported"
                )
                var secretKey =
                    cryptoVaultAES.getKeyFromAndroidKeyStore(keystoreAlias = "example_aes_2")
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% is secret key exist: ${secretKey != null}"
                )

                if (secretKey == null) {
                    secretKey = cryptoVaultAES.generateKey(
                        "example_aes_2",
                        strongBoxBacked = isStrongBoxBackedSupported
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% successfully generate secret key"
                    )
                }

                ivKey = cryptoVaultAES.generateIVGCMParameterSpecKey(12)
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% iv gcm key: $ivKey"
                )
                encryptedText = cryptoVaultAES.encrypt(
                    secretKey,
                    GCMParameterSpec(128, cryptoVaultAES.decode(ivKey)),
                    "Passw0rd!"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )

                val decryptedText = cryptoVaultAES.decrypt(
                    secretKey,
                    GCMParameterSpec(128, cryptoVaultAES.decode(ivKey)),
                    encryptedText
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )
            }
        }
    }
}