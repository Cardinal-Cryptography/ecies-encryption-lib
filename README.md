# ECIES Encryption Library

This repo contains ECIES encryption using `secp256k1` + `AES-GCM`

## 🔐 Crypto Stack

- EC key exchange via `secp256k1` (ECDH)
- AES-256-GCM for authenticated encryption
- HKDF for key derivation

---

## 🚀 Usage

See https://github.com/Cardinal-Cryptography/ecies-encryption-poc

## WARNING

Using encrypt or decrypt directly does not hide plaintext length which might be a problem in some cases. One needs do further work in order to fix that (add padding carefully).
