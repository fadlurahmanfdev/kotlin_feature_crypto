package com.fadlurahmanfdev.crypto_vault.internal.ec

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

/**
 * HKDF-SHA256 (RFC 5869) helper for deriving AES key material from an ECDH shared secret.
 */
internal object EcHkdf {
    fun derive(
        inputKeyMaterial: ByteArray,
        saltBytes: ByteArray = ByteArray(0),
        infoBytes: ByteArray = EcTransformation.defaultHkdfInfoBytes(),
        lengthBytes: Int = EcTransformation.AES_KEY_SIZE_BYTES,
    ): ByteArray {
        val output = ByteArray(lengthBytes)
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(inputKeyMaterial, saltBytes, infoBytes))
        generator.generateBytes(output, 0, lengthBytes)
        return output
    }
}
