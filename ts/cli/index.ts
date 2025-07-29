#!/usr/bin/env ts-node

import { Command } from "commander";
import {
  generateKeypair,
  toHex,
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
    console.log("Private key:", toHex(sk));
    console.log("Public key: ", toHex(pk));
  });

program
  .command("encrypt")
  .description("Encrypt a plaintext message with a public key")
  .requiredOption("-p, --pubkey <hex>", "Recipient public key (hex)")
  .requiredOption("-m, --message <text>", "Plaintext message to encrypt")
  .action(async (opts: { message: string; pubkey: string }) => {
    const cryptoAPI = await getCrypto();
    const hex = await encrypt(opts.message, opts.pubkey, cryptoAPI);
    console.log(hex);
  });

program
  .command("decrypt")
  .description("Decrypt a ciphertext with a private key")
  .requiredOption("-k, --privkey <hex>", "Private key (hex)")
  .requiredOption("-c, --ciphertext <hex>", "Ciphertext (hex)")
  .action(async (opts: { privkey: string; ciphertext: string }) => {
    const cryptoAPI = await getCrypto();
    const result = await decrypt(opts.ciphertext, opts.privkey, cryptoAPI);
    console.log(result);
  });

  program
  .command("encrypt-padded")
  .description("Encrypt a plaintext message with a public key")
  .requiredOption("-p, --pubkey <hex>", "Recipient public key (hex)")
  .requiredOption("-m, --message <text>", "Plaintext message to encrypt")
  .requiredOption("--padded-length <number>", "Padded length of the message")
  .action(async (opts: { message: string; pubkey: string; paddedLength: number }) => {
    const cryptoAPI = await getCrypto();
    const hex = await encryptPadded(opts.message, opts.pubkey, cryptoAPI, opts.paddedLength);
    console.log(hex);
  });

program
  .command("decrypt-padded")
  .description("Decrypt a ciphertext with a private key")
  .requiredOption("-k, --privkey <hex>", "Private key (hex)")
  .requiredOption("-c, --ciphertext <hex>", "Ciphertext (hex)")
  .action(async (opts: { privkey: string; ciphertext: string }) => {
    const cryptoAPI = await getCrypto();
    const result = await decryptPaddedUnchecked(opts.ciphertext, opts.privkey, cryptoAPI);
    console.log(result);
  });

program
  .command("example")
  .description("Run the ECIES example")
  .action(async () => {
    const cryptoAPI = await getCrypto();
    const { sk, pk } = generateKeypair();
    const skHex = toHex(sk);
    const pkHex = toHex(pk);

    console.log("Private key:", skHex);
    console.log("Public key: ", pkHex);

    const message = "hello from TypeScript";
    const ciphertext = await encrypt(message, pkHex, cryptoAPI);
    console.log("Ciphertext:", ciphertext);

    const decrypted = await decrypt(ciphertext, skHex, cryptoAPI);
    console.log("Decrypted:", decrypted);
  });

program.parseAsync();
