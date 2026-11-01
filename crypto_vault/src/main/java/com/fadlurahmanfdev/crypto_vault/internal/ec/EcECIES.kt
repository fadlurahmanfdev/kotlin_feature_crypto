package com.fadlurahmanfdev.crypto_vault.internal.ec

import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.core.CryptoVaultExceptionCodes
import java.nio.ByteBuffer
import java.security.KeyPair
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * ECIES-style hybrid encrypt/decrypt: ephemeral ECDH → HKDF → AES-GCM via [CryptoVaultAES].
 *
 * Payload layout:
 * `[4-byte big-endian ephemeral public key length][ephemeral public key][12-byte IV][ciphertext+tag]`.
 */
internal object EcECIES {
    fun encrypt(
        aes: CryptoVaultAES,
        ephemeralKeyPair: KeyPair,
        sharedSecretBytes: ByteArray,
        plainTextBytes: ByteArray,
        saltBytes: ByteArray = ByteArray(0),
        infoBytes: ByteArray = EcTransformation.defaultHkdfInfoBytes(),
    ): ByteArray {
        val aesKey = deriveAesKey(sharedSecretBytes, saltBytes, infoBytes)
        val gcmSpec = aes.generateGCMParameterSpec(
            ivSizeBytes = EcTransformation.GCM_IV_SIZE_BYTES,
        )
        val ciphertext = aes.encrypt(
            secretKey = aesKey,
            plainTextBytes = plainTextBytes,
            algorithmParameterSpec = gcmSpec,
        )
        val ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded
        val ivBytes = gcmSpec.iv
        return ByteBuffer.allocate(
            EcTransformation.EPH_PUBLIC_KEY_LENGTH_BYTES +
                ephemeralPublicKeyBytes.size +
                ivBytes.size +
                ciphertext.size,
        ).apply {
            putInt(ephemeralPublicKeyBytes.size)
            put(ephemeralPublicKeyBytes)
            put(ivBytes)
            put(ciphertext)
        }.array()
    }

    fun decrypt(
        aes: CryptoVaultAES,
        sharedSecretBytes: ByteArray,
        encryptedBytes: ByteArray,
        saltBytes: ByteArray = ByteArray(0),
        infoBytes: ByteArray = EcTransformation.defaultHkdfInfoBytes(),
    ): ByteArray {
        val envelope = unpack(encryptedBytes)
        val aesKey = deriveAesKey(sharedSecretBytes, saltBytes, infoBytes)
        return aes.decrypt(
            secretKey = aesKey,
            encryptedBytes = envelope.ciphertext,
            ivBytes = envelope.ivBytes,
        )
    }

    fun unpack(encryptedBytes: ByteArray): Envelope {
        if (encryptedBytes.size < EcTransformation.EPH_PUBLIC_KEY_LENGTH_BYTES +
            EcTransformation.GCM_IV_SIZE_BYTES + 1
        ) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "ECIES payload is too short",
            )
        }
        val buffer = ByteBuffer.wrap(encryptedBytes)
        val ephemeralPublicKeyLength = buffer.int
        if (ephemeralPublicKeyLength <= 0 ||
            ephemeralPublicKeyLength >
            encryptedBytes.size - EcTransformation.EPH_PUBLIC_KEY_LENGTH_BYTES -
            EcTransformation.GCM_IV_SIZE_BYTES
        ) {
            throw CryptoVaultExceptionCodes.unknown(
                message = "ECIES ephemeral public key length is invalid",
            )
        }
        val ephemeralPublicKeyBytes = ByteArray(ephemeralPublicKeyLength)
        buffer.get(ephemeralPublicKeyBytes)
        val ivBytes = ByteArray(EcTransformation.GCM_IV_SIZE_BYTES)
        buffer.get(ivBytes)
        val ciphertext = ByteArray(buffer.remaining())
        buffer.get(ciphertext)
        return Envelope(
            ephemeralPublicKeyBytes = ephemeralPublicKeyBytes,
            ivBytes = ivBytes,
            ciphertext = ciphertext,
        )
    }

    fun deriveAesKey(
        sharedSecretBytes: ByteArray,
        saltBytes: ByteArray = ByteArray(0),
        infoBytes: ByteArray = EcTransformation.defaultHkdfInfoBytes(),
    ): SecretKey {
        val keyBytes = EcHkdf.derive(
            inputKeyMaterial = sharedSecretBytes,
            saltBytes = saltBytes,
            infoBytes = infoBytes,
        )
        return SecretKeySpec(keyBytes, "AES")
    }

    data class Envelope(
        val ephemeralPublicKeyBytes: ByteArray,
        val ivBytes: ByteArray,
        val ciphertext: ByteArray,
    )
}
