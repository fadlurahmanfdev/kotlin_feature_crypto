package com.fadlurahmanfdev.example.presentation

import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.crypto_vault.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.CryptoVaultED25519
import com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESEncryptionPadding
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.domain.ExampleCryptoUseCaseImpl
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
            title = "Encrypt & Decrypt AES Simple Key CBC PKCS5Padding With Custom IV Key",
            desc = "Encrypt & Decrypt AES Simple Key CBC PKCS5Padding With Custom IV Key & Without AndroidKeyStore",
            enum = "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_CBC_PKCS5PADDING_CUSTOM_IV_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Simple Key GCM No Padding With Custom IV GCM Key",
            desc = "Encrypt & Decrypt AES Simple Key GCM No Padding With Custom IV GCM Key & Without AndroidKeyStore",
            enum = "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_GCM_NO_PADDING_CUSTOM_GCM_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Simple Key GCM No Padding With Custom IV Key",
            desc = "Encrypt & Decrypt AES Simple Key GCM No Padding With Custom IV Key & Without AndroidKeyStore",
            enum = "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_GCM_NO_PADDING_CUSTOM_IV_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Simple Key GCM No Padding With Generated IV GCM Key",
            desc = "Encrypt & Decrypt AES Simple Key GCM No Padding With Generated IV GCM Key & Without AndroidKeyStore",
            enum = "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_GCM_NO_PADDING_GENERATED_IV_GCM_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Via Android KeyStore GCM No Padding With Generated IV GCM \uD83D\uDC4D \uD83D\uDC4D \uD83D\uDC4D",
            desc = "Encrypt & Decrypt AES Via Key generated from Android KeyStore GCM No Padding With Generated IV",
            enum = "ENCRYPT_DECRYPT_AES_KEYSTORE_GCM_NO_PADDING_GENERATED_IV_GCM_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt & Decrypt AES Via Android KeyStore GCM No Padding With Custom IV GCM",
            desc = "Encrypt & Decrypt AES Via Key generated from Android KeyStore GCM No Padding With Custom IV GCM",
            enum = "ENCRYPT_DECRYPT_AES_KEYSTORE_GCM_NO_PADDING_CUSTOM_IV_GCM_KEY"
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
            "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_CBC_PKCS5PADDING_CUSTOM_IV_KEY" -> {
                val encodedSecretKey = cryptoVaultAES.generateKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encoded secret key: $encodedSecretKey"
                )

                ivKey = cryptoVaultAES.generateIVParameterSpecKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% iv spec key: $ivKey"
                )

                encryptedText =
                    cryptoVaultAES.encrypt(
                        encodedSecretKey = encodedSecretKey,
                        blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.CBC,
                        padding = CryptoVaultAESEncryptionPadding.PKCS5Padding,
                        algorithmParameterSpec = IvParameterSpec(cryptoVaultAES.decode(ivKey)),
                        plainText = "Passw0rd!"
                    )

                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )

                val decryptedText = cryptoVaultAES.decrypt(
                    encodedSecretKey = encodedSecretKey,
                    blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.CBC,
                    padding = CryptoVaultAESEncryptionPadding.PKCS5Padding,
                    algorithmParameterSpec = IvParameterSpec(cryptoVaultAES.decode(ivKey)),
                    encryptedText = encryptedText
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )
            }

            "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_GCM_NO_PADDING_CUSTOM_GCM_KEY" -> {
                val encodedSecretKey = cryptoVaultAES.generateKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encoded secret key: $encodedSecretKey"
                )

                ivKey = cryptoVaultAES.generateIVGCMParameterSpecKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% iv gcm spec key: $ivKey"
                )

                encryptedText =
                    cryptoVaultAES.encrypt(
                        encodedSecretKey = encodedSecretKey,
                        blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                        padding = CryptoVaultAESEncryptionPadding.NoPadding,
                        algorithmParameterSpec = GCMParameterSpec(
                            128,
                            cryptoVaultAES.decode(ivKey)
                        ),
                        plainText = "Passw0rd!"
                    )

                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )

                val decryptedText = cryptoVaultAES.decrypt(
                    encodedSecretKey = encodedSecretKey,
                    blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                    padding = CryptoVaultAESEncryptionPadding.NoPadding,
                    algorithmParameterSpec = GCMParameterSpec(128, cryptoVaultAES.decode(ivKey)),
                    encryptedText = encryptedText
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )
            }

            "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_GCM_NO_PADDING_CUSTOM_IV_KEY" -> {
                val encodedSecretKey = cryptoVaultAES.generateKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% secret key: $encodedSecretKey"
                )

                ivKey = cryptoVaultAES.generateIVParameterSpecKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% iv spec key: $ivKey"
                )

                encryptedText =
                    cryptoVaultAES.encrypt(
                        encodedSecretKey = encodedSecretKey,
                        blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                        padding = CryptoVaultAESEncryptionPadding.NoPadding,
                        algorithmParameterSpec = IvParameterSpec(cryptoVaultAES.decode(ivKey)),
                        plainText = "Passw0rd!"
                    )

                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )

                val decryptedText = cryptoVaultAES.decrypt(
                    encodedSecretKey = encodedSecretKey,
                    blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                    padding = CryptoVaultAESEncryptionPadding.NoPadding,
                    algorithmParameterSpec = IvParameterSpec(cryptoVaultAES.decode(ivKey)),
                    encryptedText = encryptedText
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )
            }

            "ENCRYPT_DECRYPT_AES_SIMPLE_KEY_GCM_NO_PADDING_GENERATED_IV_GCM_KEY" -> {
                val encodedSecretKey = cryptoVaultAES.generateKey()
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% secret key: $encodedSecretKey"
                )

                val encryptedModel =
                    cryptoVaultAES.encrypt(
                        encodedSecretKey = encodedSecretKey,
                        blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                        padding = CryptoVaultAESEncryptionPadding.NoPadding,
                        plainText = "Passw0rd!"
                    )
                encryptedText = encryptedModel.encryptedText
                ivKey = encryptedModel.ivKey

                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% generated iv gcm key: $ivKey"
                )

                val decryptedText = cryptoVaultAES.decrypt(
                    secretKey = SecretKeySpec(cryptoVaultAES.decode(encodedSecretKey), "AES"),
                    blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                    padding = CryptoVaultAESEncryptionPadding.NoPadding,
                    algorithmParameterSpec = GCMParameterSpec(128, cryptoVaultAES.decode(ivKey)),
                    encryptedText = encryptedText
                )
                Log.d(
                    this::class.java.simpleName,
                    "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                )
            }

            "ENCRYPT_DECRYPT_AES_KEYSTORE_GCM_NO_PADDING_GENERATED_IV_GCM_KEY" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val keyStoreAlias = "example_aes"

                    var secretKeyFromAndroidKeyStore =
                        cryptoVaultAES.getKeyFromAndroidKeyStore(keystoreAlias = keyStoreAlias)

                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% is secret key from AndroidKeyStore exist: ${secretKeyFromAndroidKeyStore != null}"
                    )

                    if (secretKeyFromAndroidKeyStore == null) {
                        try {
                            secretKeyFromAndroidKeyStore =
                                cryptoVaultAES.generateKeyFromAndroidKeyStore(
                                    keystoreAlias = keyStoreAlias,
                                    strongBoxBacked = true,
                                    blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                                    encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
                                )
                            Log.d(
                                this::class.java.simpleName,
                                "Example-CryptoVault-LOG %%% successfully generate secret key from AndroidKeyStore"
                            )
                        } catch (e: CryptoVaultException) {
                            if (e.code == "STRONG_BOX_NOT_SUPPORTED") {
                                Log.d(
                                    this::class.java.simpleName,
                                    "Example-CryptoVault-LOG %%% strong box not supported"
                                )
                                secretKeyFromAndroidKeyStore =
                                    cryptoVaultAES.generateKeyFromAndroidKeyStore(
                                        keystoreAlias = keyStoreAlias,
                                        strongBoxBacked = false,
                                        blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                                        encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
                                    )
                                Log.d(
                                    this::class.java.simpleName,
                                    "Example-CryptoVault-LOG %%% successfully generate secret key from AndroidKeyStore"
                                )
                            } else {
                                throw e
                            }
                        }
                    }

                    val encryptedModel =
                        cryptoVaultAES.encrypt(
                            secretKey = secretKeyFromAndroidKeyStore!!,
                            blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                            padding = CryptoVaultAESEncryptionPadding.NoPadding,
                            plainText = "Passw0rd!"
                        )
                    encryptedText = encryptedModel.encryptedText
                    ivKey = encryptedModel.ivKey
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% generated iv gcm key: $ivKey"
                    )

                    val decryptedText = cryptoVaultAES.decrypt(
                        secretKey = secretKeyFromAndroidKeyStore,
                        blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                        padding = CryptoVaultAESEncryptionPadding.NoPadding,
                        encryptedText = encryptedText,
                        algorithmParameterSpec = GCMParameterSpec(128, cryptoVaultAES.decode(ivKey))
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% decryptedText text: $decryptedText"
                    )
                }
            }

            "ENCRYPT_DECRYPT_AES_KEYSTORE_GCM_NO_PADDING_CUSTOM_IV_GCM_KEY" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val keystoreAlias = "example_aes_2"
                    var secretKeyFromAndroidKeyStore =
                        cryptoVaultAES.getKeyFromAndroidKeyStore(keystoreAlias = keystoreAlias)
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% is secret key exist: ${secretKeyFromAndroidKeyStore != null}"
                    )

                    if (secretKeyFromAndroidKeyStore == null) {
                        try {
                            secretKeyFromAndroidKeyStore =
                                cryptoVaultAES.generateKeyFromAndroidKeyStore(
                                    keystoreAlias = keystoreAlias,
                                    strongBoxBacked = true,
                                    blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                                    encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
                                )
                            Log.d(
                                this::class.java.simpleName,
                                "Example-CryptoVault-LOG %%% successfully generate secret key from AndroidKeyStore"
                            )
                        } catch (e: CryptoVaultException) {
                            if (e.code == "STRONG_BOX_NOT_SUPPORTED") {
                                Log.d(
                                    this::class.java.simpleName,
                                    "Example-CryptoVault-LOG %%% strong box not supported"
                                )
                                secretKeyFromAndroidKeyStore =
                                    cryptoVaultAES.generateKeyFromAndroidKeyStore(
                                        keystoreAlias = keystoreAlias,
                                        strongBoxBacked = false,
                                        blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                                        encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
                                    )
                                Log.d(
                                    this::class.java.simpleName,
                                    "Example-CryptoVault-LOG %%% successfully generate secret key from AndroidKeyStore"
                                )
                            } else {
                                throw e
                            }
                        }
                    }

                    ivKey = cryptoVaultAES.generateIVGCMParameterSpecKey()
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% iv gcm key: $ivKey"
                    )
                    encryptedText = cryptoVaultAES.encrypt(
                        secretKey = secretKeyFromAndroidKeyStore!!,
                        blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                        padding = CryptoVaultAESEncryptionPadding.NoPadding,
                        algorithmParameterSpec = GCMParameterSpec(
                            128,
                            cryptoVaultAES.decode(ivKey)
                        ),
                        plainText = "Passw0rd!"
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% encrypted text: $encryptedText"
                    )

                    val decryptedText = cryptoVaultAES.decrypt(
                        secretKey = secretKeyFromAndroidKeyStore,
                        blockMode = com.fadlurahmanfdev.crypto_vault.enums.aes.CryptoVaultAESBlockMode.GCM,
                        padding = CryptoVaultAESEncryptionPadding.NoPadding,
                        algorithmParameterSpec = GCMParameterSpec(
                            128,
                            cryptoVaultAES.decode(ivKey)
                        ),
                        encryptedText = encryptedText
                    )
                    Log.d(
                        this::class.java.simpleName,
                        "Example-CryptoVault-LOG %%% decrypted text: $decryptedText"
                    )
                }
            }
        }
    }
}