#!/usr/bin/env ts-node

import { Command } from "commander";
import {
  generateKeypair,
  toHexString,
  getCrypto,
  encrypt,
  decrypt,
  encryptPadded,
  decryptPaddedUnchecked
} from "@cardinal-cryptography/ecies-encryption-lib";

const program = new Command();
program.name("ecies").description("ECIES encryption tool").version("1.0.0");

program
  .command("generate-keypair")
  .description("Generate a new secp256k1 keypair")
  .action(() => {
    const { sk, pk } = generateKeypair();
    console.log("Private key:", toHexString(sk));
    console.log("Public key: ", toHexString(pk));
  });

program
  .command("encrypt")
  .description("Encrypt a plaintext message with a public key")
  .requiredOption("-p, --pubkey <hex>", "Recipient public key (hex)")
  .requiredOption("-m, --message <text>", "Plaintext message to encrypt")
  .action(async (opts: { message: string; pubkey: string }) => {
    const cryptoAPI = await getCrypto();
    const messageBytes = new TextEncoder().encode(opts.message);
    const encrypted = await encrypt(messageBytes, opts.pubkey, cryptoAPI);
    const encryptedHex = toHexString(encrypted);
    console.log(encryptedHex);
  });

program
  .command("decrypt")
  .description("Decrypt a ciphertext with a private key")
  .requiredOption("-k, --privkey <hex>", "Private key (hex)")
  .requiredOption("-c, --ciphertext <hex>", "Ciphertext (hex)")
  .action(async (opts: { privkey: string; ciphertext: string }) => {
    const cryptoAPI = await getCrypto();
    const result = await decrypt(opts.ciphertext, opts.privkey, cryptoAPI);
    const decryptedMessage = new TextDecoder().decode(result);
    console.log(decryptedMessage);
  });

  program
  .command("encrypt-padded")
  .description("Encrypt a plaintext message with a public key")
  .requiredOption("-p, --pubkey <hex>", "Recipient public key (hex)")
  .requiredOption("-m, --message <text>", "Plaintext message to encrypt")
  .requiredOption("--padded-length <number>", "Padded length of the message")
  .action(async (opts: { message: string; pubkey: string; paddedLength: number }) => {
    const cryptoAPI = await getCrypto();
    const messageBytes = new TextEncoder().encode(opts.message);
    const encrypted = await encryptPadded(messageBytes, opts.pubkey, opts.paddedLength, cryptoAPI);
    const encryptedHex = toHexString(encrypted);
    console.log(encryptedHex);
  });

program
  .command("decrypt-padded")
  .description("Decrypt a ciphertext with a private key")
  .requiredOption("-k, --privkey <hex>", "Private key (hex)")
  .requiredOption("-c, --ciphertext <hex>", "Ciphertext (hex)")
  .action(async (opts: { privkey: string; ciphertext: string }) => {
    const cryptoAPI = await getCrypto();
    const result = await decryptPaddedUnchecked(opts.ciphertext, opts.privkey, cryptoAPI);
    const decryptedMessage = new TextDecoder().decode(result);
    console.log(decryptedMessage);
  });

program
  .command("example")
  .description("Run the ECIES example")
  .action(async () => {
    const cryptoAPI = await getCrypto();
    const { sk, pk } = generateKeypair();
    const skHex = toHexString(sk);
    const pkHex = toHexString(pk);

    console.log("Private key:", skHex);
    console.log("Public key: ", pkHex);

    const message = "hello from TypeScript";
    const messageBytes = new TextEncoder().encode(message);
    const ciphertext = await encrypt(messageBytes, pkHex, cryptoAPI);
    const ciphertextHex = toHexString(ciphertext);
    console.log("Ciphertext:", ciphertextHex);

    const decrypted = await decrypt(ciphertextHex, skHex, cryptoAPI);
    const decryptedMessage = new TextDecoder().decode(decrypted);
    console.log("Decrypted:", decryptedMessage);
  });

program.parseAsync();
