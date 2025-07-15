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
import com.fadlurahmanfdev.crypto_vault.CryptoVaultED25519
import com.fadlurahmanfdev.crypto_vault.CryptoVaultRSA

class RSAActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    lateinit var viewModel: MainViewModel
    lateinit var cryptoVaultRSA: CryptoVaultRSA

    private val features: List<FeatureModel> = listOf<FeatureModel>(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt RSA with Simple Key",
            desc = "Encrypt & Decrypt RSA with Simple Key",
            enum = "ENCRYPT_DECRYPT_RSA_SIMPLE_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt RSA via AndroidKeyStore \uD83D\uDC4D \uD83D\uDC4D \uD83D\uDC4D",
            desc = "Encrypt & Decrypt RSA via AndroidKeyStore",
            enum = "ENCRYPT_DECRYPT_RSA_VIA_ANDROID_KEYSTORE"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Sign & Verify Text Via Android KeyStore \uD83D\uDC4D \uD83D\uDC4D \uD83D\uDC4D",
            desc = "Sign & Verify Text Via Android KeyStore",
            enum = "SIGN_PLAIN_TEXT_RSA_VIA_ANDROID_KEYSTORE"
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

        cryptoVaultRSA = CryptoVaultRSA()
        viewModel = MainViewModel(
            exampleCryptoUseCase = ExampleCryptoUseCaseImpl(
                cryptoED25519Repository = CryptoVaultED25519(),
                cryptoVaultCustomSymmetric = com.fadlurahmanfdev.crypto_vault.CryptoVaultCustomKeyVault(),
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
            "ENCRYPT_DECRYPT_RSA_SIMPLE_KEY" -> {
                val key = cryptoVaultRSA.generateKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% successfully generate rsa simple key"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% private key: ${key.privateKey}"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% public key: ${key.publicKey}"
                )

                val blockMode = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode.ECB
                val padding = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationPadding.OAEPWithSHAAndMGF1Padding

                val encryptedText = cryptoVaultRSA.encrypt(
                    encodedPublicKey = key.publicKey,
                    blockMode = blockMode,
                    padding = padding,
                    plainText = "Passw0rd!"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )

                val decryptedText = cryptoVaultRSA.decrypt(
                    encodedPrivateKey = key.privateKey,
                    blockMode = blockMode,
                    padding = padding,
                    encryptedText = encryptedText,
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )

                val signatureAlgorithm = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSASignatureAlgorithm.MD5withRSA

                val signature = cryptoVaultRSA.generateSignature(
                    encodedPrivateKey = key.privateKey,
                    signatureAlgorithm = signatureAlgorithm,
                    plainText = "Passw0rd!"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% signature: $signature"
                )

                val isVerifySignature = cryptoVaultRSA.verifySignature(
                    encodedPublicKey = key.publicKey,
                    signatureAlgorithm = signatureAlgorithm,
                    signature = signature,
                    plainText = "Passw0rd!"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% isVerifySignature: $isVerifySignature"
                )
            }

            "ENCRYPT_DECRYPT_RSA_VIA_ANDROID_KEYSTORE" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val keystoreAlias = "example_rsa"

                    // hardcoded always delete
                    cryptoVaultRSA.deleteKey(keystoreAlias)

                    var rsaPrivateKey =
                        cryptoVaultRSA.getPrivateKeyAndroidKeyStore(keystoreAlias = keystoreAlias)
                    var rsaPublicKey =
                        cryptoVaultRSA.getPublicAndroidKeyStore(keystoreAlias = keystoreAlias)

                    if (rsaPrivateKey != null && rsaPublicKey != null) {
                        Log.d(
                            this::class.java.simpleName,
                            "Example-CryptoVault-LOG %%% successfully fetch key $keystoreAlias from AndroidKeyStore"
                        )
                    } else {
                        val key =
                            cryptoVaultRSA.generateKeyFromAndroidKeyStore(
                                keystoreAlias = keystoreAlias,
                                encryptionPaddings = arrayOf(
                                    com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSAEncryptionPadding.RSA_PKCS1
                                ),
                                signaturePaddings = arrayOf(
                                    com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSASignaturePadding.RSA_PKCS1
                                )
                            )
                        rsaPrivateKey = key.private
                        rsaPublicKey = key.public
                        Log.d(
                            this::class.java.simpleName,
                            "Example-CryptoVault-LOG %%% successfully generate key via AndroidKeyStore"
                        )
                    }

                    val blockMode = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationMode.ECB
                    val padding = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSATransformationPadding.PKCS1Padding

                    val encryptedText = cryptoVaultRSA.encrypt(
                        publicKey = rsaPublicKey!!,
                        blockMode = blockMode,
                        padding = padding,
                        plainText = "Passw0rd!"
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                    )

                    val decryptedText = cryptoVaultRSA.decrypt(
                        privateKey = rsaPrivateKey!!,
                        blockMode = blockMode,
                        padding = padding,
                        encryptedText = encryptedText
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                    )
                }
            }

            "SIGN_PLAIN_TEXT_RSA_VIA_ANDROID_KEYSTORE" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val keystoreAlias = "example_rsa"
                    val rsaPrivateKey =
                        cryptoVaultRSA.getPrivateKeyAndroidKeyStore(keystoreAlias = keystoreAlias)!!
                    val rsaPublicKey =
                        cryptoVaultRSA.getPublicAndroidKeyStore(keystoreAlias = keystoreAlias)!!

                    val signatureAlgorithm = com.fadlurahmanfdev.crypto_vault.enums.rsa.CryptoVaultRSASignatureAlgorithm.MD5withRSA

                    val signature = cryptoVaultRSA.generateSignature(
                        privateKey = rsaPrivateKey,
                        signatureAlgorithm = signatureAlgorithm,
                        plainText = "Passw0rd!"
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% signature: $signature"
                    )

                    val isVerifySignature = cryptoVaultRSA.verifySignature(
                        publicKey = rsaPublicKey,
                        signatureAlgorithm = signatureAlgorithm,
                        signature = signature,
                        plainText = "Passw0rd!"
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% isVerifySignature: $isVerifySignature"
                    )
                }
            }
        }
    }
}