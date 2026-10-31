package com.fadlurahmanfdev.crypto_vault.internal.rsa

import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

internal object RsaCipherHelper {
    fun oaepParameterSpecForPadding(padding: String): AlgorithmParameterSpec? {
        if (!RsaTransformation.isOaepSha256Padding(padding)) {
            return null
        }
        return OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT,
        )
    }
}
