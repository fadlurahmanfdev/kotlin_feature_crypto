# Overview

Kotlin library that provides a cryptography solution using a repository implementation. This library provides encryption for AES, RSA & ED25519.

## Methods

### AES

#### Generate Key

Generate AES Key. It will return in format `base64`.

```kotlin
val featureAES = FeatureCryptoAES()
val key = featureAES.generateKey()
```

#### Generate IV Key

Generate Initialization Vector Key. It will return in format `base64`.

```kotlin
val featureAES = FeatureCryptoAES()
val ivKey = featureAES.generateIVKey()
```

#### Encrypt

Encrypt a plain text, it will return base64 encrypted text, otherwise if not success, it will return null.


```kotlin
val featureAES = FeatureCryptoAES()
val encryptedText = featureAES.encrypt(
    key = "encoded key",
    plainText = "plain text",
    ivKey = "encoded iv key"
)
```

| Parameter Name | Type       | Required  | Description                                                             |
|----------------|------------|-----------|-------------------------------------------------------------------------|
| `key`          | string     | Yes       | Key generated from `Generate Key`                                       |
| `ivKey`        | string     | Yes       | Vector key generated from `Generate IV Key` or `Generate Secure IV Key` |
| `plainText`    | string     | Yes       | Text to be encrypted                                                    |

#### Decrypt

Decrypt encrypted text, it will return plain text if success, otherwise it will return null.


```kotlin
val featureAES = FeatureCryptoAES()
val decryptedText = featureAES.decrypt(
  key = "encoded key",
  encryptedText = "encrypted text",
  ivKey = "encoded iv key",
)
```

| Parameter Name  | Type       | Required  | Description                                                             |
|-----------------|------------|-----------|-------------------------------------------------------------------------|
| `key`           | string     | Yes       | Key generated from `Generate Key` or `Generate Secure Key`              |
| `ivKey`         | string     | Yes       | Vector key generated from `Generate IV Key` or `Generate Secure IV Key` |
| `encryptedText` | string     | Yes       | Encrypted text                                                          |


### RSA

#### Generate Key

Generate RSA Key, it will return CryptoKey with base64 private key & base 64 public key.


```kotlin
val featureRSA = FeatureCryptoRSA()
val key = featureRSA.generateKey()
```

#### Encrypt

Encrypt plain text and return base64 encoded if success, null if not success.


```kotlin
val featureRSA = FeatureCryptoRSA()
val encryptedText = featureRSA.encrypt(
    encodedPublicKey = "{encoded string}",
    plainText = "plain text",
)
```

| Parameter Name     | Type         | Required  | Description                                                        |
|--------------------|--------------|-----------|--------------------------------------------------------------------|
| `encodedPublicKey` | string       | Yes       | Public key generated from `Generate Key`                           |
| `plainText`        | string       | Yes       | Text to be encrypted                                               |

#### Decrypt

Decrypt encrypted text, return plain text if success, return null if not success.

```kotlin
val featureRSA = FeatureCryptoRSA()
val decryptedText = featureRSA.decrypt(
    encodedPrivateKey = "encoded private key",
    encryptedText = "encrypted text",
)
```

| Parameter Name      | Type        | Required  | Description                                                        |
|---------------------|-------------|-----------|--------------------------------------------------------------------|
| `encodedPrivateKey` | string      | Yes       | Private key generated from `Generate Key`                          |
| `encryptedText`     | string      | Yes       | Encrypted Text to be decrypted                                     |

#### Generate Signature

Generate Signature from plain text, it will return base64 signature.

Signature cannot be change into plain text, it just for verify.


```kotlin
val signature = cryptoRSARepository.generateSignature(
    encodedPrivateKey = "encoded private key",
    plainText = "plain text",
    signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA256withRSA,
)
```

| Parameter Name       | Type                            | Required | Description                                |
|----------------------|---------------------------------|----------|--------------------------------------------|
| `encodedPrivateKey`  | string                          | Yes      | Private key generated from `Generate Key`  |
| `plainText`          | string                          | Yes      | Text to be signature                       |
| `signatureAlgorithm` | FeatureCryptoSignatureAlgorithm | yes      | FeatureCryptoSignatureAlgorithm method.    |


#### Verify Signature

Verify signature and plain text. It will return true if success, otherwise it will return false.


```kotlin
val isVerified = cryptoRSARepository.verifySignature(
    encodedPublicKey = "encoded public key",
    plainText = "plain text",
    signature = "signature",
    signatureAlgorithm = FeatureCryptoSignatureAlgorithm.SHA256withRSA,
)
```

| Parameter Name          | Type                            | Required | Description                                |
|-------------------------|---------------------------------|----------|--------------------------------------------|
| `encodedPublicKey`      | string                          | Yes      | Public key generated from `Generate Key`   |
| `plainText`             | string                          | Yes      | Text to be signature                       |
| `signature`             | string                          | Yes      | Signature to be verified                   |
| `signatureAlgorithm`    | FeatureCryptoSignatureAlgorithm | yes      | FeatureCryptoSignatureAlgorithm method.    |

### ED25519

#### Generate Key

Generate ED25519 Key, it will return CryptoKey with base64 private key & base64 public key.

```kotlin
val featureED25519 = FeatureCryptoED25519()
val key = featureED25519.generateKey()
```

#### Generate Signature

Generate Signature from plain text, it will return base64 signature.

Signature cannot be change into plain text, it just for verify.


```kotlin
val featureED25519 = FeatureCryptoED25519()
val signature = featureED25519.generateSignature(
    plainText = "plain text",
    encodedPrivateKey = "encoded private key",
)
```

| Parameter Name      | Type    | Required | Description                               |
|---------------------|---------|----------|-------------------------------------------|
| `encodedPrivateKey` | string  | Yes      | Private key generated from `Generate Key` |
| `plainText`         | string  | Yes      | Text to be signature                      |

#### Verify Signature

Verify signature and plain text. It will return true if success, otherwise it will return false.


```kotlin
val featureED25519 = FeatureCryptoED25519()
val isSignatureVerified = featureED25519.verifySignature(
    plainText = "plain text",
    encodedPublicKey = "encoded public key",
    signature = "signature",
)
```

| Parameter Name          | Type    | Required | Description                              |
|-------------------------|---------|----------|------------------------------------------|
| `encodedPublicKey`      | string  | Yes      | Public key generated from `Generate Key` |
| `plainText`             | string  | Yes      | Text to be signature                     |
| `signature`             | string  | Yes      | Signature to be verified                 |
