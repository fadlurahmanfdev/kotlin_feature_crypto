package com.fadlurahmanfdev.example.domain

import android.util.Log
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultCustomAsymmetricVault
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultCustomKeyVault
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultED25519
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultBlockMode
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultPadding
import com.fadlurahmanfdev.crypto_vault.enum.CryptoVaultSignatureAlgorithm
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKey
import java.security.SecureRandom
import javax.crypto.spec.IvParameterSpec

class ExampleCryptoUseCaseImpl(
    private val cryptoED25519Repository: CryptoVaultED25519,
    private val cryptoVaultCustomSymmetric: CryptoVaultCustomKeyVault,
    private val cryptoVaultCustomAsymmetric: CryptoVaultCustomAsymmetricVault = CryptoVaultCustomAsymmetricVault(),
) : ExampleCryptoUseCase {

    override fun generateED25519Key(): CryptoVaultKey = cryptoED25519Repository.generateKey()

    override fun generateED25519Signature(
        encodedPrivateKey: String,
        plainText: String,
    ): String = cryptoED25519Repository.generateSignature(
        encodedPrivateKey = encodedPrivateKey,
        plainText = plainText,
    )

    override fun exampleED25519() {
        Log.d(this::class.java.simpleName, "example ED25519")
        val plainText = "Passw0rd!Sus4hB9t"
        Log.d(this::class.java.simpleName, "plain text: $plainText")
        val key = cryptoED25519Repository.generateKey()
        Log.d(this::class.java.simpleName, "private key: ${key.privateKey}")
        Log.d(this::class.java.simpleName, "public key: ${key.publicKey}")
        val signature = cryptoED25519Repository.generateSignature(
            plainText = plainText,
            encodedPrivateKey = key.privateKey,
        )
        Log.d(this::class.java.simpleName, "signature: $signature")
        val isVerified = cryptoED25519Repository.verifySignature(
            plainText = plainText,
            encodedPublicKey = key.publicKey,
            signature = signature,
        )
        Log.d(this::class.java.simpleName, "is signature verified: $isVerified")
    }

    override fun customSymmetricCrypto() {
        val plainText = "P4ssw0rd!Sus4h!B9t"
        val transformation = "${CryptoVaultAlgorithm.ChaCha20}/${CryptoVaultBlockMode.Poly1305}/${CryptoVaultPadding.NoPadding}"
        val isSupported = cryptoVaultCustomSymmetric.isSupported(transformation = transformation)

        if (!isSupported) {
            Log.e(
                this::class.java.simpleName,
                "no supported of given transformation: $transformation",
            )
            return
        }

        val key = cryptoVaultCustomSymmetric.generateKey(CryptoVaultAlgorithm.ChaCha20)
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        val ivKey = cryptoVaultCustomSymmetric.encode(nonce)

        Log.d(this::class.java.simpleName, "key: $key")
        Log.d(this::class.java.simpleName, "iv key: $ivKey")

        val encryptedText = cryptoVaultCustomSymmetric.encrypt(
            algorithm = CryptoVaultAlgorithm.ChaCha20,
            encodedSecretKey = key,
            transformation = transformation,
            plainText = plainText,
            algorithmParameterSpec = IvParameterSpec(cryptoVaultCustomSymmetric.decode(ivKey)),
        )
        Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")

        val decryptedText = cryptoVaultCustomSymmetric.decrypt(
            algorithm = CryptoVaultAlgorithm.ChaCha20,
            encodedSecretKey = key,
            transformation = transformation,
            algorithmParameterSpec = IvParameterSpec(cryptoVaultCustomSymmetric.decode(ivKey)),
            encryptedText = encryptedText,
        )
        Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
    }

    override fun customAsymmetricCrypto() {
        val transformation = "${CryptoVaultAlgorithm.RSA}/${CryptoVaultBlockMode.ECB}/${CryptoVaultPadding.OAEPWithSHAAndMGF1Padding}"
        val isSupported = cryptoVaultCustomAsymmetric.isSupported(transformation = transformation)

        if (!isSupported) {
            Log.e(this::class.java.simpleName, "no supported of given transformation: $transformation")
            return
        }

        val key = cryptoVaultCustomAsymmetric.generateKey(CryptoVaultAlgorithm.RSA, 2048)
        Log.d(this::class.java.simpleName, "private key: ${key.privateKey}")
        Log.d(this::class.java.simpleName, "public key: ${key.publicKey}")

        val signature = cryptoVaultCustomAsymmetric.generateSignature(
            encodedPrivateKey = key.privateKey,
            plainText = "P4ssword!Sus4h",
            algorithm = CryptoVaultAlgorithm.RSA,
            signatureAlgorithm = CryptoVaultSignatureAlgorithm.SHA256withRSA,
        )
        Log.d(this::class.java.simpleName, "signature: $signature")

        val isVerify = cryptoVaultCustomAsymmetric.verifySignature(
            encodedPublicKey = key.publicKey,
            algorithm = CryptoVaultAlgorithm.RSA,
            plainText = "P4ssword!Sus4h",
            signature = signature,
            signatureAlgorithm = CryptoVaultSignatureAlgorithm.SHA256withRSA,
        )
        Log.d(this::class.java.simpleName, "is verify signature: $isVerify")

        val encryptedText = cryptoVaultCustomAsymmetric.encrypt(
            algorithm = CryptoVaultAlgorithm.RSA,
            blockMode = CryptoVaultBlockMode.ECB,
            padding = CryptoVaultPadding.OAEPWithSHAAndMGF1Padding,
            encodedPublicKey = key.publicKey,
            plainText = "P4ssword!Sus4h",
        )
        Log.d(this::class.java.simpleName, "encrypted text: $encryptedText")

        val decryptedText = cryptoVaultCustomAsymmetric.decrypt(
            algorithm = CryptoVaultAlgorithm.RSA,
            blockMode = CryptoVaultBlockMode.ECB,
            padding = CryptoVaultPadding.OAEPWithSHAAndMGF1Padding,
            encodedPrivateKey = key.privateKey,
            encryptedText = encryptedText,
        )
        Log.d(this::class.java.simpleName, "decrypted text: $decryptedText")
    }
}
