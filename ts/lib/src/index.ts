import * as secp from "@noble/secp256k1";
// import { getCrypto, generateKeypair, toHex, fromHex } from "./utils";
import { Keypair, getCrypto, generateKeypair, fromHex, toHex } from "./utils";
export { Keypair, getCrypto, generateKeypair, toHex, fromHex };

export async function encrypt(
  message: string,
  recipientPubHex: string,
  cryptoAPI: Crypto
): Promise<string> {
  const encoded = new TextEncoder().encode(message);
  const out = await _encrypt(encoded, fromHex(recipientPubHex), cryptoAPI);
  return toHex(out);
}

export async function decrypt(
  ciphertextHex: string,
  recipientSkHex: string,
  cryptoAPI: Crypto
): Promise<string> {
  const decrypted = await _decrypt(
    fromHex(ciphertextHex),
    fromHex(recipientSkHex),
    cryptoAPI
  );
  return new TextDecoder().decode(decrypted);
}

export async function encryptPadded(
  message: string,
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

  const encodedMessage = new TextEncoder().encode(message);

  encoded.set(encodedMessage, 4);
  const encrypted = await _encrypt(
    encoded,
    fromHex(recipientPubHex),
    cryptoAPI
  );
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
    fromHex(recipientSkHex),
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
    fromHex(recipientSkHex),
    cryptoAPI
  );
  return await decodePadded(decrypted);
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
  recipientPk: Uint8Array,
  cryptoAPI: Crypto
): Promise<Uint8Array> {
  const recipientPub = secp.Point.fromHex(recipientPk);
  const ephSk = secp.utils.randomPrivateKey();
  const ephPk = secp.getPublicKey(ephSk, true);

  const ephSkBigInt = BigInt(toHex(ephSk, true));
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
  recipientSkBytes: Uint8Array,
  cryptoAPI: Crypto
): Promise<Uint8Array> {
  const ephPk = secp.Point.fromHex(ciphertextBytes.slice(0, 33));
  const iv = ciphertextBytes.slice(33, 45);
  const ciphertext = ciphertextBytes.slice(45);

  const skBigInt = BigInt(toHex(recipientSkBytes, true));
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
