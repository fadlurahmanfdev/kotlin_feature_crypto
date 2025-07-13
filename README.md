# Overview

Library provides cryptography implementation, generated via Android KeyStore or Non Android KeyStore

## Methods

### AES

#### Generate Secret Key

##### Generate AES Secret Key Via Android KeyStore

```kotlin
val cryptoAES = CryptoVaultAES()
val secretKeyViaAndroidKeyStore = cryptoVaultAES.generateKeyFromAndroidKeyStore(
    keystoreAlias = "example_aes",
    strongBoxBacked = true,
    blockMode = CryptoVaultAESBlockMode.GCM,
    encryptionPadding = CryptoVaultAESEncryptionPadding.NoPadding,
)
```

##### Generate Encoded AES Secret Key Non Android KeyStore

```kotlin
val cryptoAES = CryptoVaultAES()
val encodedSecretKey = cryptoVaultAES.generateKey()
```

##### Get AES Secret Key Android KeyStore

```kotlin
val cryptoAES = CryptoVaultAES()
var secretKeyViaAndroidKeyStore = cryptoVaultAES.getKeyFromAndroidKeyStore(
    keystoreAlias = "example_aes"
)
```

#### Encrypt/Decrypt

##### Encrypt Using Secret Key From Android KeyStore With Generated IV

```kotlin
val encryptedModel = cryptoVaultAES.encrypt(
    secretKey = secretKeyViaAndroidKeyStore!!,
    blockMode = CryptoVaultAESBlockMode.GCM,
    padding = CryptoVaultAESEncryptionPadding.NoPadding,
    plainText = "Passw0rd!"
)
val encryptedText = encryptedModel.encryptedText
val encodedIV = encryptedModel.ivKey
```

##### Encrypt With Custom IV

```kotlin
val ivKey = cryptoVaultAES.generateIVGCMParameterSpecKey()
val encryptedModel = cryptoVaultAES.encrypt(
    secretKey = secretKeyViaAndroidKeyStore!!,
    blockMode = CryptoVaultAESBlockMode.GCM,
    padding = CryptoVaultAESEncryptionPadding.NoPadding,
    algorithmParameterSpec = GCMParameterSpec(
        128,
        cryptoVaultAES.decode(ivKey)
    ),
    plainText = plainText,
)
```

### RSA

#### Generate Key Pair

##### Generate RSA Key Pair Via Android KeyStore

```kotlin
val cryptoVaultRSA = CryptoVaultRSA()
val keyPairViaAndroidKeyStore = cryptoVaultRSA.generateKeyFromAndroidKeyStore(
    keystoreAlias = "example_rsa",
    encryptionPaddings = arrayOf(
        CryptoVaultRSAEncryptionPadding.RSA_PKCS1
    ),
    signaturePaddings = arrayOf(
        CryptoVaultRSASignaturePadding.RSA_PKCS1
    )
)
```

##### Get RSA Key Pair

```kotlin
val cryptoVaultRSA = CryptoVaultRSA()
val rsaPrivateKey =
    cryptoVaultRSA.getPrivateKeyAndroidKeyStore(keystoreAlias = "example_rsa")
val rsaPublicKey =
    cryptoVaultRSA.getPublicAndroidKeyStore(keystoreAlias = "example_rsa")
```

##### Generate RSA Key Pair Non Android KeyStore

```kotlin
val cryptoVaultRSA = CryptoVaultRSA()
val keyPair = cryptoVaultRSA.generateKey()
```

#### Signing

```kotlin
val cryptoVaultRSA = CryptoVaultRSA()

// Generate Signature from the plain text
val signature = cryptoVaultRSA.generateSignature(
    privateKey = rsaPrivateKey,
    signatureAlgorithm = signatureAlgorithm,
    plainText = "Passw0rd!"
)

// Verify the signature with the plain text
val isVerifySignature = cryptoVaultRSA.verifySignature(
    publicKey = rsaPublicKey,
    signatureAlgorithm = signatureAlgorithm,
    signature = signature,
    plainText = "Passw0rd!"
)
```

#### Encrypt/Decrypt

```kotlin
val cryptoVaultRSA = CryptoVaultRSA()
val encryptedText = cryptoVaultRSA.encrypt(
    publicKey = rsaPublicKey!!,
    blockMode = blockMode,
    padding = padding,
    plainText = "Passw0rd!"
)
val decryptedText = cryptoVaultRSA.decrypt(
    privateKey = rsaPrivateKey!!,
    blockMode = blockMode,
    padding = padding,
    encryptedText = encryptedText
)
```
### ED25519

#### Generate Key

```kotlin
val cryptoVaultED25519 = CryptoVaultED25519()
val key = cryptoVaultED25519.generateKey()
```

#### Generate Signature

```kotlin
val cryptoVaultED25519 = CryptoVaultED25519()
val key = cryptoVaultED25519.generateKey()
```

#### Verify Signature

```kotlin
val cryptoVaultED25519 = CryptoVaultED25519()
val key = cryptoVaultED25519.generateKey()
```