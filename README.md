# Crypto Vault

## 🙏 Support Me

If you find my apps, libraries, or plugins helpful and would like to support their development and maintenance, you can consider buying me a coffee:

- 🌍 [Support me on Ko-fi (Global)](https://ko-fi.com/fadlurahmanfdev)
- 🇮🇩 [Dukung saya di Trakteer (Indonesia)](https://trakteer.id/fadlurahmanfdev/tip)

---

Android Kotlin cryptography SDK for AES, RSA, EC, ED25519, and custom symmetric/asymmetric algorithms. Keys can be generated in software or inside Android Keystore (TEE / StrongBox when supported).

- **Min SDK:** 21
- **Current version:** `2.0.0`
- **Maven coordinates:** `com.fadlurahmanfdev:crypto_vault:2.0.0`

## Installation

```kotlin
// build.gradle.kts
dependencies {
    implementation("com.fadlurahmanfdev:crypto_vault:2.0.0")
}
```

## Package structure

Public API lives under `com.fadlurahmanfdev.crypto_vault`:

| Package     | Purpose                                                      |
|-------------|--------------------------------------------------------------|
| `api`       | Public vault classes (`CryptoVaultAES`, `CryptoVaultRSA`, …) |
| `enum`      | Algorithm, block mode, padding, and transformation enums     |
| `model`     | `CryptoVaultKey`, `CryptoVaultEncryptedModel`                |
| `exception` | `CryptoVaultException`                                       |

```kotlin
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESBlockMode
import com.fadlurahmanfdev.crypto_vault.enum.aes.CryptoVaultAESEncryptionPadding
import com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.model.CryptoVaultEncryptedModel
```

All public vault classes are `open` so you can extend and override behavior in your app.

## Exception handling

Public APIs throw `CryptoVaultException` instead of returning `null` on failure.

```kotlin
try {
    cryptoVaultAES.generateKeyFromAndroidKeyStore(
        keystoreAlias = "example_aes",
        strongBoxBacked = true,
        blockMode = CryptoVaultAESBlockMode.GCM,
        encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
    )
} catch (e: CryptoVaultException) {
    when (e.code) {
        "STRONG_BOX_NOT_SUPPORTED" -> {
            // retry with strongBoxBacked = false
        }
        else -> throw e
    }
}
```

---

## AES

Hardware-backed AES via Android Keystore, or software keys encoded as Base64.

### Generate key (Android Keystore)

```kotlin
val cryptoVaultAES = CryptoVaultAES()
val secretKey = cryptoVaultAES.generateKeyFromAndroidKeyStore(
    keystoreAlias = "example_aes",
    strongBoxBacked = true,
    blockMode = CryptoVaultAESBlockMode.GCM,
    encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
)
```

### Generate key (software)

```kotlin
val encodedSecretKey = cryptoVaultAES.generateKey()
```

### Encrypt / decrypt (generated IV)

```kotlin
val encrypted: CryptoVaultEncryptedModel = cryptoVaultAES.encrypt(
    secretKey = secretKey,
    blockMode = CryptoVaultAESBlockMode.GCM,
    padding = CryptoVaultAESEncryptionPadding.NoPadding,
    plainText = "Passw0rd!",
)
val decrypted = cryptoVaultAES.decrypt(
    secretKey = secretKey,
    blockMode = CryptoVaultAESBlockMode.GCM,
    padding = CryptoVaultAESEncryptionPadding.NoPadding,
    algorithmParameterSpec = GCMParameterSpec(128, cryptoVaultAES.decode(encrypted.ivKey)),
    encryptedText = encrypted.encryptedText,
)
```

### Encrypt with custom IV (Keystore key)

Set `randomizedEncryptionRequired = false` when the key must accept a caller-provided IV.

```kotlin
val secretKey = cryptoVaultAES.generateKeyFromAndroidKeyStore(
    keystoreAlias = "example_aes_custom_iv",
    strongBoxBacked = false,
    blockMode = CryptoVaultAESBlockMode.GCM,
    encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
    randomizedEncryptionRequired = false,
)
val ivKey = cryptoVaultAES.generateIVGCMParameterSpecKey()
val encrypted = cryptoVaultAES.encrypt(
    secretKey = secretKey,
    blockMode = CryptoVaultAESBlockMode.GCM,
    padding = CryptoVaultAESEncryptionPadding.NoPadding,
    algorithmParameterSpec = GCMParameterSpec(128, cryptoVaultAES.decode(ivKey)),
    plainText = "Passw0rd!",
)
```

---

## RSA

RSA encryption, decryption, and signing with optional Android Keystore backing.

### Generate key pair

```kotlin
val cryptoVaultRSA = CryptoVaultRSA()

// Software key pair (Base64-encoded)
val key = cryptoVaultRSA.generateKey()

// Android Keystore
val keyPair = cryptoVaultRSA.generateKeyFromAndroidKeyStore(
    keystoreAlias = "example_rsa",
    encryptionPaddings = arrayOf(CryptoVaultRSAEncryptionPadding.RSA_PKCS1),
    signaturePaddings = arrayOf(CryptoVaultRSASignaturePadding.RSA_PKCS1),
)
```

### Sign and verify

```kotlin
val signature = cryptoVaultRSA.generateSignature(
    encodedPrivateKey = key.privateKey,
    signatureAlgorithm = CryptoVaultRSASignatureAlgorithm.SHA256withRSA,
    plainText = "Passw0rd!",
)
val isValid = cryptoVaultRSA.verifySignature(
    encodedPublicKey = key.publicKey,
    signatureAlgorithm = CryptoVaultRSASignatureAlgorithm.SHA256withRSA,
    signature = signature,
    plainText = "Passw0rd!",
)
```

### Encrypt and decrypt

```kotlin
val encrypted = cryptoVaultRSA.encrypt(
    encodedPublicKey = key.publicKey,
    blockMode = CryptoVaultRSATransformationMode.ECB,
    padding = CryptoVaultRSATransformationPadding.OAEPWithSHAAndMGF1Padding,
    plainText = "Passw0rd!",
)
val decrypted = cryptoVaultRSA.decrypt(
    encodedPrivateKey = key.privateKey,
    blockMode = CryptoVaultRSATransformationMode.ECB,
    padding = CryptoVaultRSATransformationPadding.OAEPWithSHAAndMGF1Padding,
    encryptedText = encrypted,
)
```

---

## EC (Elliptic Curve)

ECDSA signing, ECDH key exchange, and hybrid encryption (`ECDH + AES-GCM`).

### Generate key pair

```kotlin
val cryptoVaultEC = CryptoVaultEC()
val key = cryptoVaultEC.generateKey()
```

### Sign and verify

```kotlin
val signature = cryptoVaultEC.generateSignature(
    encodedPrivateKey = key.privateKey,
    plainText = "Passw0rd!",
    signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
)
val isValid = cryptoVaultEC.verifySignature(
    encodedPublicKey = key.publicKey,
    signature = signature,
    plainText = "Passw0rd!",
    signatureAlgorithm = CryptoVaultECSignatureAlgorithm.SHA256withECDSA,
)
```

### Encrypt and decrypt (ECDH + AES-GCM)

Uses an ephemeral EC key per encryption. Widely supported on Android without third-party JCE cipher aliases.

```kotlin
val encrypted = cryptoVaultEC.encrypt(
    encodedPublicKey = key.publicKey,
    transformation = CryptoVaultECTransformation.ECDH_AES_GCM,
    plainText = "Passw0rd!",
)
val decrypted = cryptoVaultEC.decrypt(
    encodedPrivateKey = key.privateKey,
    transformation = CryptoVaultECTransformation.ECDH_AES_GCM,
    encryptedText = encrypted,
)
```

### Key exchange (ECDH)

```kotlin
val aliceKey = cryptoVaultEC.generateKey()
val bobKey = cryptoVaultEC.generateKey()

val aliceSharedSecret = cryptoVaultEC.generateSharedSecret(
    ourEncodedPrivateKey = aliceKey.privateKey,
    otherEncodedPublicKey = bobKey.publicKey,
)
val aesKey = cryptoVaultEC.derivedSharedSecret(aliceSharedSecret)
```

---

## ED25519

Software ED25519 signing via BouncyCastle.

```kotlin
val cryptoVaultED25519 = CryptoVaultED25519()
val key = cryptoVaultED25519.generateKey()

val signature = cryptoVaultED25519.generateSignature(
    encodedPrivateKey = key.privateKey,
    plainText = "Passw0rd!",
)
val isValid = cryptoVaultED25519.verifySignature(
    encodedPublicKey = key.publicKey,
    plainText = "Passw0rd!",
    signature = signature,
)
```

---

## Custom symmetric crypto

`CryptoVaultCustomKeyVault` supports algorithms such as AES, ChaCha20, DES, and 3DES with custom transformations.

```kotlin
val customVault = CryptoVaultCustomKeyVault()
val transformation = "${CryptoVaultAlgorithm.ChaCha20}/${CryptoVaultBlockMode.Poly1305}/${CryptoVaultPadding.NoPadding}"

if (customVault.isSupported(transformation)) {
    val key = customVault.generateKey(CryptoVaultAlgorithm.ChaCha20)
    val nonce = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
    val encrypted = customVault.encrypt(
        algorithm = CryptoVaultAlgorithm.ChaCha20,
        encodedSecretKey = key,
        transformation = transformation,
        plainText = "Passw0rd!",
        algorithmParameterSpec = javax.crypto.spec.IvParameterSpec(nonce),
    )
}
```

---

## Custom asymmetric crypto

`CryptoVaultCustomAsymmetricVault` supports generic RSA/EC-style sign, verify, encrypt, and decrypt.

```kotlin
val customVault = CryptoVaultCustomAsymmetricVault()
val key = customVault.generateKey(CryptoVaultAlgorithm.RSA, 2048)

val signature = customVault.generateSignature(
    encodedPrivateKey = key.privateKey,
    plainText = "Passw0rd!",
    algorithm = CryptoVaultAlgorithm.RSA,
    signatureAlgorithm = CryptoVaultSignatureAlgorithm.SHA256withRSA,
)
```

---

## Migration guide (v1.x → v2.0)

### Package imports

| Before (v1.x)                                                | After (v2.0)                                            |
|--------------------------------------------------------------|---------------------------------------------------------|
| `com.fadlurahmanfdev.crypto_vault.CryptoVaultAES`            | `com.fadlurahmanfdev.crypto_vault.api.CryptoVaultAES`   |
| `com.fadlurahmanfdev.crypto_vault.enums.*`                   | `com.fadlurahmanfdev.crypto_vault.enum.*`               |
| `com.fadlurahmanfdev.crypto_vault.data.model.CryptoVaultKey` | `com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKey` |

### EC encryption

| Before                                        | After                                      |
|-----------------------------------------------|--------------------------------------------|
| `CryptoVaultECTransformation.ECIESwithAESCBC` | `CryptoVaultECTransformation.ECDH_AES_GCM` |

v2.0 uses ephemeral ECDH + SHA-256 KDF + AES-GCM. Ciphertext produced by v1.x ECIES is **not** compatible with v2.0 decrypt.

### AES Keystore custom IV

When encrypting with a caller-provided IV on a Keystore-backed key, pass `randomizedEncryptionRequired = false` to `generateKeyFromAndroidKeyStore`. Without this, Android throws `InvalidAlgorithmParameterException: Caller-provided IV not permitted`.

### Signature verification

`verifySignature` now returns the actual result of `Signature.verify()`. Previously some implementations always returned `true` when no exception was thrown.

### Exception model

`CryptoVaultException` now includes an optional `cause: Throwable?` field.

```kotlin
data class CryptoVaultException(
    val code: String,
    override val message: String? = null,
    override val cause: Throwable? = null,
)
```

---

## Sample app

The `app` module demonstrates every public vault feature. Run it from Android Studio or:

```bash
./gradlew :app:installDebug
```

## License

Apache License 2.0
