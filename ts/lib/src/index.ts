import * as secp from "@noble/secp256k1";
import { TextEncoder, TextDecoder } from "util";


export function toHex(uint8: Uint8Array): string {
  return Array.from(uint8)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

export async function getCrypto(): Promise<Crypto> {
  return typeof globalThis.crypto !== "undefined"
    ? globalThis.crypto
    : ((await import("node:crypto")).webcrypto as Crypto);
}

export type Keypair = { sk: Uint8Array; pk: Uint8Array };

export function generateKeypair(): Keypair {
  const sk = secp.utils.randomPrivateKey();
  const pk = secp.getPublicKey(sk, true);
  return { sk, pk };
}

async function hkdf(
  sharedSecret: Uint8Array,
  cryptoAPI: Crypto
): Promise<CryptoKey> {
  const keyMaterial = await cryptoAPI.subtle.importKey(
    "raw",
    sharedSecret as BufferSource,
    "HKDF",
    false,
    ["deriveKey"]
  );
  return await cryptoAPI.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array([]),
      info: new TextEncoder().encode("ecies-secp256k1-v1") as BufferSource,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function _encrypt(
  message: Uint8Array,
  recipientPubHex: string,
  cryptoAPI: Crypto
): Promise<Uint8Array> {
  const recipientPub = secp.Point.fromHex(recipientPubHex);
  const ephSk = secp.utils.randomPrivateKey();
  const ephPk = secp.getPublicKey(ephSk, true);

  const ephSkBigInt = BigInt("0x" + toHex(ephSk));
  const shared = recipientPub.multiply(ephSkBigInt).toRawBytes(true);
  const aesKey = await hkdf(shared, cryptoAPI);

  const iv = cryptoAPI.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await cryptoAPI.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    message as BufferSource
  );
  const ciphertext = new Uint8Array(ciphertextBuffer);

  const out = new Uint8Array(ephPk.length + iv.length + ciphertext.length);
  out.set(ephPk);
  out.set(iv, ephPk.length);
  out.set(ciphertext, ephPk.length + iv.length);

  return out;
}

async function _decrypt(
  ciphertextBytes: Uint8Array,
  recipientSkHex: string,
  cryptoAPI: Crypto
): Promise<Uint8Array> {
  const ephPk = secp.Point.fromHex(ciphertextBytes.slice(0, 33));
  const iv = ciphertextBytes.slice(33, 45);
  const ciphertext = ciphertextBytes.slice(45);

  const skBytes = fromHex(recipientSkHex);
  const skBigInt = BigInt("0x" + toHex(skBytes));
  const shared_point = ephPk.multiply(skBigInt);
  let shared = shared_point.toRawBytes(true);
  const aesKey = await hkdf(shared, cryptoAPI);

  const plaintextBuffer = await cryptoAPI.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    ciphertext as BufferSource
  );
  return new Uint8Array(plaintextBuffer);
}

export async function encrypt(
  message: string,
  recipientPubHex: string,
  cryptoAPI: Crypto
): Promise<string> {
  const encoded = new TextEncoder().encode(message);
  const out = await _encrypt(encoded, recipientPubHex, cryptoAPI);
  return toHex(out);
}

export async function decrypt(
  ciphertextHex: string,
  recipientSkHex: string,
  cryptoAPI: Crypto
): Promise<string> {
  const decrypted = await _decrypt(
    fromHex(ciphertextHex),
    recipientSkHex,
    cryptoAPI
  );
  return new TextDecoder().decode(decrypted);
}

export async function encryptPadded(
  message: string | Uint8Array,
  recipientPubHex: string,
  cryptoAPI: Crypto,
  paddedLength: number
): Promise<string> {
  if (paddedLength < message.length + 4) {
    throw new Error(
      `Invalid padded length ${paddedLength} bytes, expected at least ${
        message.length + 4
      } bytes)`
    );
  }
  let encoded = new Uint8Array(paddedLength);

  // prepend with the message length info in little endian (4 bytes)
  const buffer = new ArrayBuffer(4);
  const view = new DataView(buffer);
  view.setUint32(0, message.length, true);
  encoded.set(new Uint8Array(buffer), 0);

  const encodedMessage = message instanceof Uint8Array ? message : new TextEncoder().encode(message);

  encoded.set(encodedMessage, 4);
  const encrypted = await _encrypt(encoded, recipientPubHex, cryptoAPI);
  return toHex(encrypted);
}

export async function decryptPadded(
  ciphertextHex: string,
  recipientSkHex: string,
  cryptoAPI: Crypto,
  paddedLength: number
): Promise<string> {
  const decrypted = await _decrypt(
    fromHex(ciphertextHex),
    recipientSkHex,
    cryptoAPI
  );
  if (decrypted.length != paddedLength) {
    throw new Error(
      `Invalid padded length ${decrypted.length} bytes, expected ${paddedLength} bytes)`
    );
  }
  return decodePadded(decrypted);
}

export async function decryptPaddedUnchecked(
  ciphertextHex: string,
  recipientSkHex: string,
  cryptoAPI: Crypto
): Promise<string> {
  const decrypted = await _decrypt(
    fromHex(ciphertextHex),
    recipientSkHex,
    cryptoAPI
  );
  return await decodePadded(decrypted);
}

async function decodePadded(paddedMessage: Uint8Array): Promise<string> {
  if (paddedMessage.length < 4) {
    throw new Error(
      `Invalid padded length ${
        paddedMessage.length
      } bytes, expected at least ${4} bytes)`
    );
  }
  const view = new DataView(paddedMessage.buffer);
  const messageLength = view.getUint32(0, true);

  if (messageLength > paddedMessage.length - 4) {
    throw new Error(
      `Invalid message length ${messageLength} bytes, expected at most ${
        paddedMessage.length - 4
      } bytes)`
    );
  }

  return new TextDecoder().decode(paddedMessage.subarray(4, messageLength + 4));
}
