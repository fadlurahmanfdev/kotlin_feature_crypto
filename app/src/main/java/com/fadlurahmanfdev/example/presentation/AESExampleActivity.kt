package com.fadlurahmanfdev.example.presentation

import com.fadlurahmanfdev.example.R
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.domain.runner.AesExampleRunner

class AESExampleActivity : AlgorithmExampleActivity() {

    private val runner = AesExampleRunner()

    override val toolbarTitle: String = "AES Examples"

    override val features: List<FeatureModel> = listOf(
        FeatureModel(
            featureIcon = R.drawable.ic_algorithm_aes,
            title = "Android Keystore GCM, No Padding, Generated IV",
            desc = "Keys stored in Android Keystore, GCM Block Mode, No Padding, and with auto-generated GCM IV",
            enum = "ANDROID_KEYSTORE_AES_GCM_NO_PADDING_GENERATED_IV",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_scenario_encrypt,
            title = "Android Keystore CBC, PKCS7, Generated IV",
            desc = "Android Keystore AES key with CBC mode and PKCS7 with Generated IV",
            enum = "ANDROID_KEYSTORE_AES_CBC_PKCS7_GENERATED_IV",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_scenario_encrypt,
            title = "Software AES GCM, No Padding (generated IV)",
            desc = "Software AES GCM, No Padding with Generated IV.",
            enum = "SOFTWARE_AES_GCM_GENERATED_IV",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_scenario_encrypt,
            title = "Software AES Key GCM, No Padding (custom IV)",
            desc = "Software AES Key GCM, No Padding with custom IV Parameter Spec",
            enum = "SOFTWARE_AES_GCM_CUSTOM_IV",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_scenario_encrypt,
            title = "Software AES Key, GCM, No Padding (Custom GCM Parameter Spec)",
            desc = "Software  AES GCM, No Padding with Custom GCM parameter spec.",
            enum = "SOFTWARE_AES_GCM_CUSTOM_GCM_IV",
        ),
        FeatureModel(
            featureIcon = R.drawable.ic_scenario_encrypt,
            title = "Software AES Key CBC + PKCS5 (custom IV)",
            desc = "Software AES key CBC mode and PKCS5 padding using a custom IV Parameter Spec",
            enum = "SOFTWARE_AES_CBC_PKCS5_CUSTOM_IV",
        ),
    )

    override fun onClicked(item: FeatureModel) {
//        val result = when (item.enum) {
//            "ANDROID_KEYSTORE_AES_GCM_NO_PADDING_GENERATED_IV" -> runner.runKeystoreGcmNoPaddingGeneratedIv()
//            "ANDROID_KEYSTORE_AES_CBC_PKCS7_GENERATED_IV" -> runner.runKeystoreCbcPkcs7GeneratedIv()
//            "SOFTWARE_AES_GCM_GENERATED_IV" -> runner.runGcmNoPaddingWithGeneratedIv()
//            "SOFTWARE_AES_GCM_CUSTOM_IV" -> runner.runGcmNoPaddingCustomIvParameterSpec()
//            "SOFTWARE_AES_GCM_CUSTOM_GCM_IV" -> runner.runGcmNoPaddingCustomGcmParameterSpec()
//            "SOFTWARE_AES_CBC_PKCS5_CUSTOM_IV" -> runner.runCbcPkcs5CustomIv()
//            else -> return
//        }
//        showResult(result)
    }
}
