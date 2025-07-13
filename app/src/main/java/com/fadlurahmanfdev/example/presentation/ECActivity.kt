package com.fadlurahmanfdev.example.presentation

import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.domain.ExampleCryptoUseCaseImpl
import com.fadlurahmanfdev.kotlin_feature_crypto.CryptoVaultEC
import com.fadlurahmanfdev.kotlin_feature_crypto.CryptoVaultED25519
import com.fadlurahmanfdev.kotlin_feature_crypto.CryptoVaultCustomKeyVault
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm
import com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECTransformation

class ECActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    lateinit var viewModel: MainViewModel
    lateinit var cryptoVaultEC: CryptoVaultEC
    var encodedPrivateKey: String? = null
    var encodedPublicKey: String? = null
    var signatureText: String? = null
    var signatureAlgorithm = com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm.SHA256withECDSA

    private val features: List<FeatureModel> = listOf<FeatureModel>(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Example Generate Key, Encrypt, Decrypt, Sign & Verify EC",
            desc = "Example Generate Key, Encrypt, Decrypt, Sign & Verify EC",
            enum = "EXAMPLE_EC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Example EC Key Exchange",
            desc = "Example EC Key Exchange",
            enum = "EXAMPLE_EC_KEY_EXCHANGE"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Generate EC Key via AndroidKeyStore \uD83D\uDC4D \uD83D\uDC4D \uD83D\uDC4D",
            desc = "Generate EC Key via AndroidKeyStore",
            enum = "GENERATE_EC_KEY_VIA_KEYSTORE"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Sign & Verify via AndroidKeyStore \uD83D\uDC4D \uD83D\uDC4D \uD83D\uDC4D",
            desc = "Sign & Verify via AndroidKeyStore",
            enum = "SIGN_VERIFY_VIA_KEYSTORE"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Generate EC Key via Non Android KeyStore",
            desc = "Generate EC Key via Non Android KeyStore",
            enum = "GENERATE_EC_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Sign & Verify via Non Android KeyStore",
            desc = "Sign & Verify via Non Android KeyStore",
            enum = "SIGN_VERIFY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt via Non Android KeyStore",
            desc = "Encrypt & Decrypt via Non Android KeyStore",
            enum = "ENCRYPT_DECRYPT"
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

        cryptoVaultEC = CryptoVaultEC()
        viewModel = MainViewModel(
            exampleCryptoUseCase = ExampleCryptoUseCaseImpl(
                cryptoED25519Repository = CryptoVaultED25519(),
                cryptoVaultCustomSymmetric = CryptoVaultCustomKeyVault(),
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
            "EXAMPLE_EC" -> {
                val key = cryptoVaultEC.generateKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% successfully generate key"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% private key: ${key.privateKey}"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% public key: ${key.publicKey}"
                )

                val transformation = com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECTransformation.ECIESwithAESCBC
                val encryptedText = cryptoVaultEC.encrypt(
                    encodedPublicKey = key.publicKey,
                    transformation = transformation,
                    plainText = "Passw0rd!"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )

                val decryptedText = cryptoVaultEC.decrypt(
                    encodedPrivateKey = key.privateKey,
                    transformation = transformation,
                    encryptedText = encryptedText
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )

                val signatureText = cryptoVaultEC.generateSignature(
                    encodedPrivateKey = key.privateKey,
                    plainText = "Passw0rd!",
                    signatureAlgorithm = com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm.SHA256withECDSA
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% signature text: $signatureText"
                )

                val isVerified = cryptoVaultEC.verifySignature(
                    encodedPublicKey = key.publicKey,
                    signature = signatureText,
                    plainText = "Passw0rd!",
                    signatureAlgorithm = com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm.SHA256withECDSA
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% is verify: $isVerified"
                )
            }

            "EXAMPLE_EC_KEY_EXCHANGE" -> {
                val bobKey = cryptoVaultEC.generateKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% successfully generate bob key"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% bob private key: ${bobKey.privateKey}"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% bob public key: ${bobKey.publicKey}"
                )

                val aliceKey = cryptoVaultEC.generateKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% successfully generate alice key"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% alice private key: ${aliceKey.privateKey}"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% alice public key: ${aliceKey.publicKey}"
                )

                val bobSharedSecret = cryptoVaultEC.generateSharedSecret(
                    ourEncodedPrivateKey = bobKey.privateKey,
                    otherEncodedPublicKey = aliceKey.publicKey
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% bob shared secret: $bobSharedSecret"
                )

                val keyFromBobSharedSecret =
                    cryptoVaultEC.derivedSharedSecret(sharedSecret = bobSharedSecret)
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% key from bob shared secret: $keyFromBobSharedSecret"
                )

                val aliceSharedSecret = cryptoVaultEC.generateSharedSecret(
                    ourEncodedPrivateKey = aliceKey.privateKey,
                    otherEncodedPublicKey = bobKey.publicKey
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% alice shared secret: $aliceSharedSecret"
                )
                val keyFromAliceSharedSecret =
                    cryptoVaultEC.derivedSharedSecret(sharedSecret = aliceSharedSecret)
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% key from alice shared secret: $keyFromAliceSharedSecret"
                )
            }

            "GENERATE_EC_KEY_VIA_KEYSTORE" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val keystoreAlias = "example_ec"

                    var ecPrivateKey =
                        cryptoVaultEC.getPrivateKeyAndroidKeyStore(keystoreAlias = keystoreAlias)
                    var ecPublicKey =
                        cryptoVaultEC.getPublicAndroidKeyStore(keystoreAlias = keystoreAlias)

                    if (ecPrivateKey != null && ecPublicKey != null) {
                        Log.d(
                            this::class.java.simpleName,
                            "Example-CryptoVault-LOG %%% successfully fetch key $keystoreAlias from AndroidKeyStore"
                        )
                    } else {
                        val key =
                            cryptoVaultEC.generateKeyFromAndroidKeyStore(
                                keystoreAlias = keystoreAlias,
                                strongBoxBacked = false
                            )
                        ecPrivateKey = key.private
                        ecPublicKey = key.public
                        Log.d(
                            this::class.java.simpleName,
                            "Example-CryptoVault-LOG %%% successfully generate key via AndroidKeyStore"
                        )
                    }

                    val signatureAlgorithm = com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm.SHA256withECDSA

                    val signatureText = cryptoVaultEC.generateSignature(
                        privateKey = ecPrivateKey!!,
                        signatureAlgorithm = signatureAlgorithm,
                        plainText = "Passw0rd!"
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% signature text: $signatureText"
                    )
                }
            }

            "SIGN_VERIFY_VIA_KEYSTORE" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val keystoreAlias = "example_ec"

                    var ecPrivateKey =
                        cryptoVaultEC.getPrivateKeyAndroidKeyStore(keystoreAlias = keystoreAlias)
                    var ecPublicKey =
                        cryptoVaultEC.getPublicAndroidKeyStore(keystoreAlias = keystoreAlias)

                    if (ecPrivateKey != null && ecPublicKey != null) {
                        Log.d(
                            this::class.java.simpleName,
                            "Example-CryptoVault-LOG %%% successfully fetch key $keystoreAlias from AndroidKeyStore"
                        )
                    } else {
                        val key =
                            cryptoVaultEC.generateKeyFromAndroidKeyStore(
                                keystoreAlias = keystoreAlias,
                                strongBoxBacked = false
                            )
                        ecPrivateKey = key.private
                        ecPublicKey = key.public
                        Log.d(
                            this::class.java.simpleName,
                            "Example-CryptoVault-LOG %%% successfully generate key via AndroidKeyStore"
                        )
                    }

                    val signatureAlgorithm = com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm.SHA256withECDSA

                    val signatureText = cryptoVaultEC.generateSignature(
                        privateKey = ecPrivateKey!!,
                        signatureAlgorithm = signatureAlgorithm,
                        plainText = "Passw0rd!"
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% signature text: $signatureText"
                    )

                    val isVerified = cryptoVaultEC.verifySignature(
                        publicKey = ecPublicKey!!,
                        plainText = "Passw0rd!",
                        signature = signatureText,
                        signatureAlgorithm = signatureAlgorithm
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% is verified: $isVerified"
                    )
                }
            }

            "GENERATE_EC_KEY" -> {
                val key = cryptoVaultEC.generateKey()
                encodedPrivateKey = key.privateKey
                encodedPublicKey = key.publicKey
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% successfully generate key"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% private key: $encodedPrivateKey"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% public key: $encodedPublicKey"
                )

                signatureAlgorithm = com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECSignatureAlgorithm.SHA256withECDSA

                signatureText = cryptoVaultEC.generateSignature(
                    encodedPrivateKey = encodedPrivateKey!!,
                    signatureAlgorithm = signatureAlgorithm,
                    plainText = "Passw0rd!"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% signature text: $signatureText"
                )


            }

            "SIGN_VERIFY" -> {
                val isVerified = cryptoVaultEC.verifySignature(
                    encodedPublicKey = encodedPublicKey!!,
                    plainText = "Passw0rd!",
                    signature = signatureText!!,
                    signatureAlgorithm = signatureAlgorithm
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% is verified: $isVerified"
                )
            }

            "ENCRYPT_DECRYPT" -> {
                val encryptedText =  cryptoVaultEC.encrypt(
                    encodedPublicKey = encodedPublicKey!!,
                    transformation = com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECTransformation.ECIESwithAESCBC,
                    plainText = "Passw0rd!",
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )

                val decryptedText =  cryptoVaultEC.decrypt(
                    encodedPrivateKey = encodedPrivateKey!!,
                    transformation = com.fadlurahmanfdev.kotlin_feature_crypto.enums.ec.CryptoVaultECTransformation.ECIESwithAESCBC,
                    encryptedText = encryptedText,
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )
            }
        }
    }
}