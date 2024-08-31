# Overview

Kotlin library that provides a cryptography solution using a repository implementation. This library provides encryption for AES, RSA & ED25519.

## Methods

### AES

#### Generate Key

Generate AES Key. It will return in format `base64`.

```kotlin
val key = cryptoAESRepository.generateKey()
// or
val key = cryptoAESRepository.generateSecureKey()
```

#### Generate IV Key

Generate Initialization Vector Key. It will return in format `base64`.

```kotlin
val ivKey = cryptoAESRepository.generateIVKey()
```

#### Encrypt

Encrypt a plain text, it will return base64 encrypted text, otherwise if not success, it will return null.


```kotlin
val encryptedText = cryptoAESRepository.encrypt(
    key = key,
    plainText = plainText,
    ivKey = ivKey
)
```

| Parameter Name | Type       | Required  | Description                                                             |
|----------------|------------|-----------|-------------------------------------------------------------------------|
| `key`          | string     | Yes       | Key generated from `Generate Key` or `Generate Secure Key`              |
| `ivKey`        | string     | Yes       | Vector key generated from `Generate IV Key` or `Generate Secure IV Key` |
| `plainText`    | string     | Yes       | Text to be encrypted                                                    |
| `method`       | AESMethod  | no        | AES Encryption mode, default is `AESMethod.AES_CBC_PKCS5PADDING`        |

#### Decrypt

Decrypt encrypted text, it will return plain text if success, otherwise it will return null.


```kotlin
val decryptedText = cryptoAESRepository.decrypt(
  key = key,
  encryptedText = encryptedText,
  ivKey = ivKey,
)
```

| Parameter Name  | Type       | Required  | Description                                                             |
|-----------------|------------|-----------|-------------------------------------------------------------------------|
| `key`           | string     | Yes       | Key generated from `Generate Key` or `Generate Secure Key`              |
| `ivKey`         | string     | Yes       | Vector key generated from `Generate IV Key` or `Generate Secure IV Key` |
| `encryptedText` | string     | Yes       | Encrypted text                                                          |
| `method`        | AESMethod  | no        | AES Encryption method, default is `AESMethod.AES_CBC_PKCS5PADDING`      |


### RSA

#### Generate Key

Generate RSA Key, it will return CryptoKey with base64 private key & base 64 public key.


```kotlin
val key = cryptoRSARepository.generateKey()
```

#### Encrypt

Encrypt plain text and return base64 encoded if success, null if not success.


```kotlin
val encryptedText = cryptoRSARepository.encrypt(
    publicKey = publicKey,
    plainText = plainText,
    method = RSAMethod.RSA_ECB_PKCS1Padding
)
```

| Parameter Name  | Type         | Required  | Description                                                        |
|-----------------|--------------|-----------|--------------------------------------------------------------------|
| `publicKey`     | string       | Yes       | Public key generated from `Generate Key`                           |
| `plainText`     | string       | Yes       | Text to be encrypted                                               |
| `method`        | AESMethod    | no        | RSA Encryption method, default is `RSAMethod.RSA_ECB_PKCS1Padding` |

#### Decrypt

Decrypt encrypted text, return plain text if success, return null if not success.

```kotlin
val decryptedText = cryptoRSARepository.decrypt(
    privateKey = privateKey,
    encryptedText = encryptedText,
    method = RSAMethod.RSA_ECB_PKCS1Padding,
)
```

| Parameter Name  | Type        | Required  | Description                                                        |
|-----------------|-------------|-----------|--------------------------------------------------------------------|
| `privateKey`    | string      | Yes       | Private key generated from `Generate Key`                          |
| `encryptedText` | string      | Yes       | Encrypted Text to be decrypted                                     |
| `method`        | AESMethod   | no        | RSA Encryption method, default is `RSAMethod.RSA_ECB_PKCS1Padding` |

#### Generate Signature

Generate Signature from plain text, it will return base64 signature.
Signature cannot be change into plain text, it just for verify.


```kotlin
val signature = cryptoRSARepository.generateSignature(
    privateKey = privateKey,
    plainText = plainText,
    method = RSASignatureMethod.SHA256withRSA,
)
```

| Parameter Name  | Type               | Required | Description                               |
|-----------------|--------------------|----------|-------------------------------------------|
| `privateKey`    | string             | Yes      | Private key generated from `Generate Key` |
| `plainText`     | string             | Yes      | Text to be signature                      |
| `method`        | RSASignatureMethod | yes      | RSASignatureMethod method.                |


#### Verify Signature

Verify signature and plain text. It will return true if success, otherwise it will return false.


```kotlin
val isVerified = cryptoRSARepository.verifySignature(
    publicKey = publicKey,
    plainText = plainText,
    signature = signature,
    method = RSASignatureMethod.SHA256withRSA,
)
```

| Parameter Name | Type               | Required | Description                              |
|----------------|--------------------|----------|------------------------------------------|
| `publicKey`    | string             | Yes      | Public key generated from `Generate Key` |
| `plainText`    | string             | Yes      | Text to be signature                     |
| `signature`    | string             | Yes      | Signature to be verified                 |
| `method`       | RSASignatureMethod | yes      | RSASignatureMethod method.               |

### ED25519

#### Generate Key

Generate ED25519 Key, it will return CryptoKey with base64 private key & base64 public key.

```kotlin
val key = cryptoED25519Repository.generateKey()
```

#### Generate Signature

Generate Signature from plain text, it will return base64 signature.
Signature cannot be change into plain text, it just for verify.


```kotlin
val signature = cryptoED25519Repository.generateSignature(
    plainText = plainText,
    privateKey = privateKey,
)
```

| Parameter Name  | Type               | Required | Description                               |
|-----------------|--------------------|----------|-------------------------------------------|
| `privateKey`    | string             | Yes      | Private key generated from `Generate Key` |
| `plainText`     | string             | Yes      | Text to be signature                      |

#### Verify Signature

Verify signature and plain text. It will return true if success, otherwise it will return false.


```kotlin
val isSignatureVerified = cryptoED25519Repository.verifySignature(
    plainText = plainText,
    publicKey = publicKey,
    signature = signature,
)
```

| Parameter Name | Type               | Required | Description                              |
|----------------|--------------------|----------|------------------------------------------|
| `publicKey`    | string             | Yes      | Public key generated from `Generate Key` |
| `plainText`    | string             | Yes      | Text to be signature                     |
| `signature`    | string             | Yes      | Signature to be verified                 |
