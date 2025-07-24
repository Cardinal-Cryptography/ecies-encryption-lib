# ECIES Encryption Library

This repo contains ECIES encryption using `secp256k1` + `AES-GCM`

## 🔐 Crypto Stack

- EC key exchange via `secp256k1` (ECDH)
- AES-256-GCM for authenticated encryption
- HKDF for key derivation

## 📂 Project Structure

- `rust/`
    - `lib/` — Full keygen + ECIES encrypt/decrypt in Rust
    - `cli/` — `clap`-based CLI
- `ts/`
    - `lib/` — TypeScript ECIES using `@noble/secp256k1` + WebCrypto
    - `cli/` — `commander`-based CLI

---
## Integration test
We include an integration test for JS <--> Rust compatibility.
```
./ecies-integration-test.sh
```

## 🚀 Usage

```bash
git clone https://github.com/Cardinal-Cryptography/ecies-encryption-lib.git
cd ecies-encryption-lib
```

Run the rust example
```bash
cargo build
./target/debug/ecies-encryption-cli example
```

Or run subcommands like:

```bash
./target/debug/ecies-encryption-cli generate-keypair
./target/debug/ecies-encryption-cli encrypt --pubkey <hex> --message "hello"
./target/debug/ecies-encryption-cli decrypt --privkey <hex> --ciphertext <hex>
```

Run the TypeScript example

```bash
pnpm install
pnpm build
```
Then
```bash
pnpm tsx ./ts/cli/index.ts example
pnpm tsx ./ts/cli/index.ts generate-keypair
pnpm tsx ./ts/cli/index.ts encrypt --pubkey <hex> --message "hello"
pnpm tsx ./ts/cli/index.ts decrypt --privkey <hex> --ciphertext <hex>
```

## WARNING

Using encrypt or decrypt directly does not hide plaintext length which might be a problem in some cases. One needs do further work in order to fix that (add padding carefully).
