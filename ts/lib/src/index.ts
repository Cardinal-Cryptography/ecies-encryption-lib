import * as secp from "@noble/secp256k1";
import { TextEncoder, TextDecoder } from "util";

export function toHex(buf: Uint8Array): string {
  return Buffer.from(buf).toString("hex");
}

export function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

export async function getCrypto(): Promise<Crypto> {
  return typeof globalThis.crypto !== "undefined"
    ? globalThis.crypto
    : (await import("node:crypto")).webcrypto as Crypto;
}

type Keypair = { sk: Uint8Array; pk: Uint8Array };

export function generateKeypair(): Keypair {
  const sk = secp.utils.randomPrivateKey();
  const pk = secp.getPublicKey(sk, true);
  return { sk, pk };
}

async function hkdf(sharedSecret: Uint8Array, cryptoAPI: Crypto): Promise<CryptoKey> {
  const keyMaterial = await cryptoAPI.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  return cryptoAPI.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array([]),
      info: new TextEncoder().encode("ecies-secp256k1-v1"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encrypt(message: string, recipientPubHex: string, cryptoAPI: Crypto): Promise<string> {
  const recipientPub = secp.Point.fromHex(recipientPubHex);
  const ephSk = secp.utils.randomPrivateKey();
  const ephPk = secp.getPublicKey(ephSk, true);

  const ephSkBigInt = BigInt("0x" + toHex(ephSk));
  const shared = recipientPub.multiply(ephSkBigInt).toRawBytes(true);
  const aesKey = await hkdf(shared, cryptoAPI);

  const iv = cryptoAPI.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(message);

  const ciphertextBuffer = await cryptoAPI.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encoded);
  const ciphertext = new Uint8Array(ciphertextBuffer);

  const out = new Uint8Array(ephPk.length + iv.length + ciphertext.length);
  out.set(ephPk);
  out.set(iv, ephPk.length);
  out.set(ciphertext, ephPk.length + iv.length);

  return toHex(out);
}

export async function decrypt(ciphertextHex: string, recipientSkHex: string, cryptoAPI: Crypto): Promise<string> {

  
  const bytes = fromHex(ciphertextHex);
  const ephPk = secp.Point.fromHex(bytes.slice(0, 33));
  const iv = bytes.slice(33, 45);
  const ciphertext = bytes.slice(45);

  
  const skBytes = fromHex(recipientSkHex);
  const skBigInt = BigInt("0x" + toHex(skBytes));
  const shared_point = ephPk.multiply(skBigInt);
  let shared = shared_point.toRawBytes(true);
  const aesKey = await hkdf(shared, cryptoAPI);

  const plaintextBuffer = await cryptoAPI.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
  return new TextDecoder().decode(plaintextBuffer);
}
