package co.id.fadlurahmanf.core_crypto_v2.others

import co.id.fadlurahmanf.core_crypto_v2.data.enums.AESMethod
import co.id.fadlurahmanf.core_crypto_v2.data.enums.RSAMethod
import co.id.fadlurahmanf.core_crypto_v2.data.enums.RSASignatureMethod
import java.util.Base64

abstract class BaseCrypto {

    open fun encode(byte: ByteArray): String {
        return Base64.getEncoder().encodeToString(byte)
    }

    open fun decode(text: String): ByteArray {
        return Base64.getDecoder().decode(text.toByteArray())
    }

    open fun decode(byte: ByteArray): ByteArray {
        return Base64.getDecoder().decode(byte)
    }

    fun getAESTransformationBasedOnFlow(method: AESMethod): String {
        return when (method) {
            AESMethod.AES_CBC_ISO10126Padding -> "AES/CBC/ISO10126Padding"
            AESMethod.AES_GCM_NoPadding -> "AES/GCM/NoPadding"
        }
    }

    fun getRSASignatureAlgorithmBasedOnFlow(method: RSASignatureMethod): String {
        return when (method) {
            RSASignatureMethod.MD5withRSA -> "MD5withRSA"
            RSASignatureMethod.SHA1withRSA -> "SHA1withRSA"
            RSASignatureMethod.SHA256withRSA -> "SHA256withRSA"
            RSASignatureMethod.SHA384withRSA -> "SHA384withRSA"
            RSASignatureMethod.SHA512withRSA -> "SHA512withRSA"
        }
    }

    fun getRSATransformationBasedOnFlow(method: RSAMethod): String {
        return when (method) {
            RSAMethod.RSA_ECB_NoPadding -> "RSA/ECB/NoPadding"
            RSAMethod.RSA_ECB_OAEPPadding -> "RSA/ECB/OAEPPadding"
            RSAMethod.RSA_ECB_PKCS1Padding -> "RSA/ECB/PKCS1Padding"
        }
    }
}