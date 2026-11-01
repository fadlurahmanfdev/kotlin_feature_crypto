# Crypto Vault

## 🙏 Support Me

If you find my apps, libraries, or plugins helpful and would like to support their development and maintenance, you can consider buying me a coffee:

- 🌍 [Support me on Ko-fi (Global)](https://ko-fi.com/fadlurahmanfdev)
- 🇮🇩 [Dukung saya di Trakteer (Indonesia)](https://trakteer.id/fadlurahmanfdev/tip)

---

Android Kotlin cryptography SDK for AES, RSA, EC, ED25519, and custom symmetric/asymmetric algorithms. Keys can be generated in software or inside Android Keystore (TEE / StrongBox when supported).

- **Min SDK:** 24
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

Library code is organized by layer under `com.fadlurahmanfdev.crypto_vault`:

| Package | Purpose |
|---------|---------|
| `api` / `api.aes` / `api.rsa` | Public vault classes (`CryptoVaultAES`, `CryptoVaultAESAndroidKeyStore`, `CryptoVaultRSA`, `CryptoVaultRSAAndroidKeyStore`, …) |
| `api.base` | Open base classes for extending vault behavior |
| `api.enums` | Shared algorithm enums (for example custom vault algorithms) |
| `core.exception` | `CryptoVaultException` |
| `model` | `CryptoVaultKey`, `CryptoVaultEncryptedModel` |
| `enum` | Backward-compatible aliases to `core.enum` |
| `enums` | Backward-compatible aliases to `core.enum` (v1.x plural package) |
| `exception` | Backward-compatible alias to `core.exception` |

Dependency rules:

- `model` and `core` depend on nothing
- `api` depends on `model` and `core`
- `internal` depends on `api`, `model`, and `core`

Recommended imports for new code:

```kotlin
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAESAndroidKeyStore
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException
import com.fadlurahmanfdev.crypto_vault.model.EncryptedData
```

All public vault classes are `open` so you can extend and override behavior in your app.

## Exception handling

Public APIs throw `CryptoVaultException` instead of returning `null` on failure.

```kotlin
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAESAndroidKeyStore
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException

val aes = CryptoVaultAESAndroidKeyStore.create()
try {
    aes.generateKey(
        keyStoreAlias = "example_aes",
        strongBoxBacked = true,
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

Two open APIs cover the two key scenarios:

| Class | Key type |
|-------|----------|
| `CryptoVaultAES` | Software AES key (exportable, lives in app memory) |
| `CryptoVaultAESAndroidKeyStore` | Android Keystore AES key (non-exportable, TEE / StrongBox) |

Defaults for both: **AES-256-GCM** (`blockMode = "GCM"`, `padding = "NoPadding"`), Cipher-generated IV,
`ByteArray` plaintext/ciphertext, and [`EncryptedData`](crypto_vault/src/main/java/com/fadlurahmanfdev/crypto_vault/domain/models/EncryptedData.kt)
(`text` + `iv`).

`blockMode` and `padding` are plain `String` values for the JCA form `AES/{blockMode}/{padding}`.
Pass any Android/JCA segment (for example `"CBC"`, `"PKCS7Padding"`, `"CTR"`). Unsupported
combinations fail with `CryptoVaultException`.

```kotlin
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES
import com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAESAndroidKeyStore
import com.fadlurahmanfdev.crypto_vault.model.EncryptedData
import javax.crypto.SecretKey
```

### Software key (`CryptoVaultAES`)

Prefer Android Keystore when the key never needs to leave the device. With software keys you must
store the key bytes securely yourself.

`keySize` supports **128 or 256** bits (default 256). Unsupported sizes throw `INVALID_KEY_SIZE`.

```kotlin
val aes = CryptoVaultAES.create()
val secretKey: SecretKey = aes.generateKey()
val secretKey128: SecretKey = aes.generateKey(keySize = 128)

val encrypted: EncryptedData = aes.encrypt(
    secretKey = secretKey,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
)
val decrypted: ByteArray = aes.decrypt(
    secretKey = secretKey,
    encryptedBytes = encrypted.encryptedBytes,
    ivBytes = encrypted.ivBytes,
)

// Custom IV / GCM tag via AlgorithmParameterSpec
val gcmSpec = aes.generateGCMParameterSpec()
val cipherOnly: ByteArray = aes.encrypt(
    secretKey = secretKey,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
    algorithmParameterSpec = gcmSpec,
)
val plainAgain: ByteArray = aes.decrypt(
    secretKey = secretKey,
    encryptedBytes = cipherOnly,
    algorithmParameterSpec = gcmSpec,
)

// Legacy CBC interop (explicit non-default)
val ivSpec = aes.generateIvParameterSpec()
val cbcCipher: ByteArray = aes.encrypt(
    secretKey = secretKey,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
    blockMode = "CBC",
    padding = "PKCS7Padding",
    algorithmParameterSpec = ivSpec,
)
```

Import an existing key with `parseKey(keyBytes)`.

| Code | When |
|------|------|
| `INVALID_KEY_SIZE` | `keySize` is not 128 or 256 |
| `INTEGRITY_CHECK_FAILED` | GCM ciphertext or IV was modified |
| `INVALID_BLOCK_MODE` | IV-only decrypt used a block mode other than GCM/CBC |
| `UNKNOWN` | Any other generation / encrypt / decrypt failure |

### Android Keystore key (`CryptoVaultAESAndroidKeyStore`)

Keys are generated inside Android Keystore. Material never leaves the Keystore.
Defaults: AES-256, GCM, no padding, randomized encryption required, StrongBox off.
Generating again for the same alias replaces the old key.

```kotlin
val aes = CryptoVaultAESAndroidKeyStore.create()
val secretKey: SecretKey = aes.generateKey(keyStoreAlias = "example_aes")

// StrongBox + extra KeyGenParameterSpec options
val strongBoxKey: SecretKey = aes.generateKey(
    keyStoreAlias = "example_aes_strongbox",
    strongBoxBacked = true,
) {
    setUserAuthenticationRequired(true)
}

val loaded: SecretKey = aes.getKey(keyStoreAlias = "example_aes")
    ?: aes.generateKey(keyStoreAlias = "example_aes")

val encrypted: EncryptedData = aes.encrypt(
    secretKey = secretKey,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
)
val plainTextBytes: ByteArray = aes.decrypt(
    secretKey = secretKey,
    encryptedBytes = encrypted.encryptedBytes,
    ivBytes = encrypted.ivBytes,
)
```

Full escape hatch: `generateKey(algorithmParameterSpec)` with your own `KeyGenParameterSpec`.

| Code | When |
|------|------|
| `INVALID_KEY_ALIAS` | `keyStoreAlias` is blank |
| `INVALID_KEY_SIZE` | `keySize` is not 128 or 256 |
| `STRONG_BOX_NOT_SUPPORTED` | `strongBoxBacked = true` but StrongBox is unavailable |
| `KEY_PERMANENTLY_INVALIDATED` | Key was invalidated (for example biometric enrollment changed) |
| `USER_NOT_AUTHENTICATED` | Key requires user authentication that has not happened yet |
| `INTEGRITY_CHECK_FAILED` | GCM ciphertext or IV was modified, or belongs to a different key |
| `INVALID_BLOCK_MODE` | Decrypt used a block mode other than GCM/CBC |
| `UNKNOWN` | Any other Keystore / cipher failure |

---

## RSA

RSA uses two public entry points:

| Class | Use when |
|-------|----------|
| `CryptoVaultRSA` | Software RSA key pair (exportable, lives in app memory) |
| `CryptoVaultRSAAndroidKeyStore` | Android Keystore RSA key pair (non-exportable, TEE / StrongBox) |

Defaults: **2048-bit** keys, encrypt/decrypt with
`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`, software signatures with `SHA256withRSA`,
Keystore signatures with `SHA256withRSA/PSS` (keys are generated with OAEP + PSS paddings).
I/O is `ByteArray` (no Base64 inside the vault). `blockMode`, `padding`, and
`signatureAlgorithm` are plain JCA `String` segments.

```kotlin
import com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSA
import com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSAAndroidKeyStore
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
```

### Software key (`CryptoVaultRSA`)

Prefer Android Keystore when the private key never needs to leave the device. With software keys
you must store key bytes securely yourself.

`keySize` supports **2048, 3072, or 4096** bits (default 2048). Unsupported sizes throw
`INVALID_KEY_SIZE`.

```kotlin
val rsa = CryptoVaultRSA.create()
val keyPair: KeyPair = rsa.generateKey()

val encryptedBytes: ByteArray = rsa.encrypt(
    publicKey = keyPair.public,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
)
val decrypted: ByteArray = rsa.decrypt(
    privateKey = keyPair.private,
    encryptedBytes = encrypted,
)

val signature: ByteArray = rsa.sign(
    privateKey = keyPair.private,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
)
val isValid: Boolean = rsa.verify(
    publicKey = keyPair.public,
    signature = signature,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
)
```

Import existing keys with `parsePublicKey(byteArray)` / `parsePrivateKey(byteArray)`.
Escape hatch: pass `algorithmParameterSpec` on encrypt/decrypt for custom OAEP (or other) specs.

| Code | When |
|------|------|
| `INVALID_KEY_SIZE` | `keySize` is not 2048, 3072, or 4096 |
| `UNKNOWN` | Any other generation / encrypt / decrypt / sign / verify setup failure |

`verify` returns `false` only when the signature does not match; unexpected setup errors throw
`UNKNOWN`.

### Android Keystore key (`CryptoVaultRSAAndroidKeyStore`)

Keys are generated inside Android Keystore. Private material never leaves the Keystore.
Defaults: RSA-2048, encryption padding `OAEPPadding`, signature padding `PSS`, digests
`SHA-256` / `SHA-512`, StrongBox off. Generating again for the same alias replaces the old key.

```kotlin
val rsa = CryptoVaultRSAAndroidKeyStore.create()
val keyPair: KeyPair = rsa.generateKey(keyStoreAlias = "example_rsa")

// StrongBox + extra KeyGenParameterSpec options
val strongBoxKey: KeyPair = rsa.generateKey(
    keyStoreAlias = "example_rsa_strongbox",
    strongBoxBacked = true,
) {
    setUserAuthenticationRequired(true)
}

val privateKey: PrivateKey = rsa.getPrivateKey("example_rsa")
    ?: rsa.generateKey(keyStoreAlias = "example_rsa").private
val publicKey: PublicKey = rsa.getPublicKey("example_rsa")!!

val encryptedBytes: ByteArray = rsa.encrypt(
    publicKey = publicKey,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
)
val plainTextBytes: ByteArray = rsa.decrypt(
    privateKey = privateKey,
    encryptedBytes = encrypted,
)

val signature: ByteArray = rsa.sign(
    privateKey = privateKey,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
)
val isValid: Boolean = rsa.verify(
    publicKey = publicKey,
    signature = signature,
    plainTextBytes = "Passw0rd!".toByteArray(Charsets.UTF_8),
)
```

Full escape hatch: `generateKey(algorithmParameterSpec)` with your own `KeyGenParameterSpec`.

| Code | When |
|------|------|
| `INVALID_KEY_ALIAS` | `keyStoreAlias` is blank |
| `INVALID_KEY_SIZE` | `keySize` is not 2048, 3072, or 4096 |
| `STRONG_BOX_NOT_SUPPORTED` | `strongBoxBacked = true` but StrongBox is unavailable |
| `KEY_PERMANENTLY_INVALIDATED` | Key was invalidated (for example biometric enrollment changed) |
| `USER_NOT_AUTHENTICATED` | Key requires user authentication that has not happened yet |
| `UNKNOWN` | Any other Keystore / cipher / signature failure |

---


## EC (Elliptic Curve)

ECDSA (`SHA256withECDSA`), ECDH key exchange, and ECIES-style hybrid encryption
(ephemeral ECDH → HKDF-SHA256 → AES-256-GCM via `CryptoVaultAES`). Keys default to NIST P-256.

```kotlin
import com.fadlurahmanfdev.crypto_vault.api.ec.CryptoVaultEC
```

### Generate key pair

```kotlin
val cryptoVaultEC = CryptoVaultEC.create()
val key = cryptoVaultEC.generateKey()
```

### Sign and verify

```kotlin
val plainTextBytes = "Passw0rd!".toByteArray()
val signatureBytes = cryptoVaultEC.generateSignature(
    privateKeyBytes = key.private.encoded,
    plainTextBytes = plainTextBytes,
)
val isValid = cryptoVaultEC.verifySignature(
    publicKeyBytes = key.public.encoded,
    signatureBytes = signatureBytes,
    plainTextBytes = plainTextBytes,
)
```

### Encrypt and decrypt (ECIES)

Uses an ephemeral P-256 key per encryption. Envelope layout:
`[4-byte eph pub length][eph pub][12-byte IV][ciphertext+tag]`.
AES-GCM is performed by `CryptoVaultAES`.

```kotlin
val encryptedBytes = cryptoVaultEC.encrypt(
    recipientPublicKeyBytes = key.public.encoded,
    plainTextBytes = plainTextBytes,
)
val decryptedBytes = cryptoVaultEC.decrypt(
    recipientPrivateKeyBytes = key.private.encoded,
    encryptedBytes = encryptedBytes,
)
```

### Key exchange (ECDH + HKDF)

```kotlin
val aliceKey = cryptoVaultEC.generateKey()
val bobKey = cryptoVaultEC.generateKey()

val aliceSharedSecret = cryptoVaultEC.generateSharedSecret(
    ephemeralPrivateKeyBytes = aliceKey.private.encoded,
    recipientPublicKeyBytes = bobKey.public.encoded,
)
val aesKey = cryptoVaultEC.deriveAESKey(sharedSecretBytes = aliceSharedSecret)
// Then encrypt with CryptoVaultAES.create().encrypt(secretKey = aesKey, ...)
```

---

## ED25519

Software ED25519 signing via BouncyCastle.

```kotlin
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultED25519
```

```kotlin
val cryptoVaultED25519 = CryptoVaultED25519()
val key = cryptoVaultED25519.generateKey()

val signature = cryptoVaultED25519.generateSignature(
    privateKeyBytes = key.private.encoded,
    plainText = "Passw0rd!",
)
val isValid = cryptoVaultED25519.verifySignature(
    publicKeyBytes = key.public.encoded,
    plainText = "Passw0rd!",
    signature = signature,
)
```

---

## Custom symmetric crypto

`CryptoVaultCustomKeyVault` supports algorithms such as AES, ChaCha20, DES, and 3DES with custom transformations.

```kotlin
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultCustomKeyVault
import com.fadlurahmanfdev.crypto_vault.core.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.core.enum.CryptoVaultBlockMode
import com.fadlurahmanfdev.crypto_vault.core.enum.CryptoVaultPadding
```

```kotlin
val customVault = CryptoVaultCustomKeyVault()
val transformation = "${CryptoVaultAlgorithm.ChaCha20}/${CryptoVaultBlockMode.Poly1305}/${CryptoVaultPadding.NoPadding}"

if (customVault.isSupported(transformation)) {
    val key = customVault.generateKey(CryptoVaultAlgorithm.ChaCha20)
    val nonce = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
    val encryptedBytes = customVault.encrypt(
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
import com.fadlurahmanfdev.crypto_vault.api.CryptoVaultCustomAsymmetricVault
import com.fadlurahmanfdev.crypto_vault.core.enum.CryptoVaultAlgorithm
import com.fadlurahmanfdev.crypto_vault.core.enum.CryptoVaultSignatureAlgorithm
```

```kotlin
val customVault = CryptoVaultCustomAsymmetricVault()
val key = customVault.generateKey(CryptoVaultAlgorithm.RSA, 2048)

val signature = customVault.generateSignature(
    privateKeyBytes = key.private.encoded,
    plainText = "Passw0rd!",
    algorithm = CryptoVaultAlgorithm.RSA,
    signatureAlgorithm = CryptoVaultSignatureAlgorithm.SHA256withRSA,
)
```

---

## Migration guide (v1.x → v2.0)

### Package imports

| Before (v1.x) | After (v2.0 recommended) | Still supported |
|---------------|----------------------------|-----------------|
| Legacy monolithic AES API | `com.fadlurahmanfdev.crypto_vault.api.aes.CryptoVaultAES` / `CryptoVaultAESAndroidKeyStore` | Removed |
| Legacy monolithic RSA API + RSA enums | `com.fadlurahmanfdev.crypto_vault.api.rsa.CryptoVaultRSA` / `CryptoVaultRSAAndroidKeyStore` | Removed |
| `com.fadlurahmanfdev.crypto_vault.enums.*` | `com.fadlurahmanfdev.crypto_vault.core.enum.*` | `enum.*` and `enums.*` typealiases |
| `com.fadlurahmanfdev.crypto_vault.enum.*` | `com.fadlurahmanfdev.crypto_vault.core.enum.*` | `enum.*` typealias |
| `com.fadlurahmanfdev.crypto_vault.exception.CryptoVaultException` | `com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException` | `exception.*` typealias |
| `com.fadlurahmanfdev.crypto_vault.data.model.CryptoVaultKey` | `com.fadlurahmanfdev.crypto_vault.model.CryptoVaultKey` | — |
| `com.fadlurahmanfdev.crypto_vault.internal.base.*` | `com.fadlurahmanfdev.crypto_vault.api.base.*` | `internal.base.*` typealias |

### EC encryption

| Before                                        | After                                      |
|-----------------------------------------------|--------------------------------------------|
| `CryptoVaultECTransformation.ECIESwithAESCBC` | `CryptoVaultECTransformation.ECDH_AES_GCM` |

v2.0 uses ephemeral ECDH + SHA-256 KDF + AES-GCM. Ciphertext produced by v1.x ECIES is **not** compatible with v2.0 decrypt.

### AES Keystore custom IV

`CryptoVaultAESAndroidKeyStore.encrypt` always uses a Cipher-generated IV (randomized encryption).
Do not pass a caller IV for Keystore encrypt. For custom IV software paths, use
`CryptoVaultAES.encrypt(..., algorithmParameterSpec = ...)`.

### Signature verification

`verifySignature` now returns the actual result of `Signature.verify()`. Previously some implementations always returned `true` when no exception was thrown.

### Exception model

`CryptoVaultException` lives in `core.exception` and is thrown by public APIs instead of returning `null` on failure.

```kotlin
import com.fadlurahmanfdev.crypto_vault.core.exception.CryptoVaultException

data class CryptoVaultException(
    val code: String,
    override val message: String? = null,
    override val cause: Throwable? = null,
)
```

Common error codes:

| Code | When |
|------|------|
| `STRONG_BOX_NOT_SUPPORTED` | StrongBox was requested but the device does not support it |
| `INVALID_KEY_SIZE` | AES key size is not 128/256, or RSA key size is not 2048/3072/4096 |
| `INVALID_KEY_ALIAS` | Keystore alias is blank |
| `KEY_PERMANENTLY_INVALIDATED` | Android Keystore key was permanently invalidated |
| `USER_NOT_AUTHENTICATED` | Keystore key requires user authentication first |
| `INTEGRITY_CHECK_FAILED` | GCM authentication failed (tampered ciphertext/IV) |
| `INVALID_BLOCK_MODE` | Decrypt could not map the given block mode to a parameter spec |
| `KEY_TYPE_MISMATCH` | Keystore alias exists but is not the expected key algorithm/type |
| `KEY_NOT_FOUND` | Keystore alias does not exist or key material is missing |
| `UNKNOWN` | Unexpected Keystore or crypto failure |
| `UNSUPPORTED_EC_TRANSFORMATION` | EC encrypt/decrypt called with an unsupported transformation |

---

## Sample app

The `app` module demonstrates every public vault feature. Run it from Android Studio or:

```bash
./gradlew :app:installDebug
```

## License

Apache License 2.0
