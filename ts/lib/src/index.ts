import * as secp from "@noble/secp256k1";

export type Keypair = { sk: Uint8Array; pk: Uint8Array };

/** * Generates a new keypair using secp256k1.
 * The private key (sk) is a random 32-byte Uint8Array,
 * and the public key (pk) is derived from the private key.
 * @returns A Keypair object containing the private key (sk) and public key (pk).
 */
export function generateKeypair(): Keypair {
  const sk = secp.utils.randomPrivateKey();
  const pk = secp.getPublicKey(sk, true);
  return { sk, pk };
}

/** * Converts a private key (sk) to a public key (pk).
 * The private key can be provided as a Uint8Array or a hex string.
 * @param sk The private key to convert. It can be a Uint8Array or a hex string.
 * @returns The public key as a Uint8Array.
 * @throws Error if the private key length is not 32 bytes.
 */
export function publicKeyFromPrivateKey(sk: Uint8Array | string): Uint8Array {
  const privateKey = convertToBytes(sk);
  if (privateKey.length !== 32) {
    throw new Error("Invalid private key length, expected 32 bytes");
  }
  return secp.getPublicKey(privateKey, true);
}

/**
 * Gets the appropriate Crypto API to use.
 * @returns The global Crypto API or the Node.js crypto module.
 * If the global Crypto API is not available, it will import the Node.js crypto module.
 */
export async function getCrypto(): Promise<Crypto> {
  return typeof globalThis.crypto !== "undefined"
    ? globalThis.crypto
    : ((await import("node:crypto")).webcrypto as Crypto);
}

/**
 * Converts a Uint8Array to a hex string.
 * @param bytes The Uint8Array to convert.
 * @param withPrefix If true, the hex string will be prefixed with "0x".
 * @returns The hex string representation of the Uint8Array.
 */
export function toHexString(
  bytes: Uint8Array,
  withPrefix: boolean = false
): string {
  const hex = Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return withPrefix ? "0x" + hex : hex;
}

/**
 * Converts a hex string to a Uint8Array.
 * @param {string} hex The hex string to convert. It can optionally start with "0x" or "0X".
 * @returns {Uint8Array} The Uint8Array representation of the hex string.
 * @throws Error if the hex string has an odd length.
 */
export function fromHexString(hex: string): Uint8Array {
  hex = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.slice(i, i + 2), 16);
    if (isNaN(byte)) {
      throw new Error("Failed to parse hex string");
    }
    bytes[i / 2] = byte;
  }
  return bytes;
}

/**
 * Converts the input to a Uint8Array.
 * If the input is a hex string, it converts it to a Uint8Array.
 * If the input is already a Uint8Array, it returns it as is.
 * @param {Uint8Array | string} hex The input to convert to a Uint8Array. It can be a hex string or a Uint8Array.
 * @returns {Uint8Array} A Uint8Array representation of the input.
 */
export function convertToBytes(hex: Uint8Array | string): Uint8Array {
  return isBytes(hex)
    ? Uint8Array.from(hex as Uint8Array)
    : fromHexString(hex as string);
}

function isBytes(bytes: Uint8Array | string): boolean {
  return (
    bytes instanceof Uint8Array ||
    (ArrayBuffer.isView(bytes) && bytes.constructor.name === "Uint8Array")
  );
}
/**
 * Encrypts a message using the recipient's public key.
 * @param {Uint8Array | string} messageBytes The message to encrypt. It can be a hex string or a Uint8Array.
 * @param {Uint8Array | string} recipientPubKeyBytes The recipient's public key. It can be a hex string or a Uint8Array.
 * @param {Crypto} [cryptoAPI] The crypto API to use. See getCrypto() for details.
 *                  If not provided, the global crypto API will be used.
 * @returns {Promise<Uint8Array>} The encrypted message.
 */
export async function encrypt(
  messageBytes: Uint8Array | string,
  recipientPubKeyBytes: Uint8Array | string,
  cryptoAPI?: Crypto
): Promise<Uint8Array> {
  const out = await _encrypt(
    convertToBytes(messageBytes),
    convertToBytes(recipientPubKeyBytes),
    cryptoAPI
  );
  return out;
}

/** * Decrypts a message using the recipient's private key.
 * @param {Uint8Array | string} ciphertextBytes The encrypted message to decrypt. It can be a hex string or a Uint8Array.
 * @param {Uint8Array | string} recipientSkBytes The recipient's private key. It can be a hex string or a Uint8Array.
 * @param {Crypto} [cryptoAPI] The crypto API to use. See getCrypto() for details.
 *                   If not provided, the global crypto API will be used.
 * @returns {Promise<Uint8Array>} The decrypted message.
 */
export async function decrypt(
  ciphertextBytes: Uint8Array | string,
  recipientSkBytes: Uint8Array | string,
  cryptoAPI?: Crypto
): Promise<Uint8Array> {
  const decrypted = await _decrypt(
    convertToBytes(ciphertextBytes),
    convertToBytes(recipientSkBytes),
    cryptoAPI
  );
  return decrypted;
}

/**
 * Encrypts a message with padding to a specified length.
 * The first 4 bytes of the encrypted message will contain the original message length in little-endian format.
 * @param {Uint8Array | string} messageBytes The message to encrypt. It can be a hex string or a Uint8Array.
 * @param {Uint8Array | string} recipientPubKeyBytes The recipient's public key. It can be a hex string or a Uint8Array.
 * @param {Crypto} [cryptoAPI] The crypto API to use. See getCrypto() for details.
 *                  If not provided, the global crypto API will be used.
 * @param {number} paddedLength The total length of the padded message in bytes.
 * @returns {Promise<Uint8Array>} The encrypted padded message.
 */
export async function encryptPadded(
  messageBytes: Uint8Array | string,
  recipientPubKeyBytes: Uint8Array | string,
  paddedLength: number,
  cryptoAPI?: Crypto
): Promise<Uint8Array> {
  const encodedMessage = convertToBytes(messageBytes);
  if (paddedLength < encodedMessage.length + 4) {
    throw new Error(
      `Invalid padded length ${paddedLength} bytes, expected at least ${
        encodedMessage.length + 4
      } bytes)`
    );
  }
  let encoded = new Uint8Array(paddedLength);

  // prepend with the message length info in little endian (4 bytes)
  const buffer = new ArrayBuffer(4);
  const view = new DataView(buffer);
  view.setUint32(0, encodedMessage.length, true);
  encoded.set(new Uint8Array(buffer), 0);

  encoded.set(encodedMessage, 4);
  const encrypted = await _encrypt(
    encoded,
    convertToBytes(recipientPubKeyBytes),
    cryptoAPI
  );
  return encrypted;
}

/**
 * Decrypts a padded message using the recipient's private key.
 * The first 4 bytes of the encrypted message should contain the original message length in little-endian format.
 * @param {Uint8Array | string} ciphertextBytes The encrypted padded message to decrypt. It can be a hex string or a Uint8Array.
 * @param {Uint8Array | string} recipientSkBytes The recipient's private key. It can be a hex string or a Uint8Array.
 * @param {Crypto} cryptoAPI The crypto API to use. See getCrypto() for details.
 * @param {number} paddedLength The expected total length of the padded message in bytes.
 * @returns {Promise<Uint8Array>} The decrypted padded message.
 */
export async function decryptPadded(
  ciphertextBytes: Uint8Array | string,
  recipientSkBytes: Uint8Array | string,
  paddedLength: number,
  cryptoAPI?: Crypto
): Promise<Uint8Array> {
  const decrypted = await _decrypt(
    convertToBytes(ciphertextBytes),
    convertToBytes(recipientSkBytes),
    cryptoAPI
  );
  if (decrypted.length != paddedLength) {
    throw new Error(
      `Invalid padded length ${decrypted.length} bytes, expected ${paddedLength} bytes)`
    );
  }
  return decodePadded(decrypted);
}

/**
 * Decrypts a padded message without checking the padded length.
 * The first 4 bytes of the encrypted message should contain the original message length in little-endian format.
 * This function does not check if the decrypted message length matches the expected padded length.
 * Use with caution.
 * @param {Uint8Array | string} ciphertextBytes The encrypted padded message to decrypt. It can be a hex string or a Uint8Array.
 * @param {Uint8Array | string} recipientSkBytes The recipient's private key. It can be a hex string or a Uint8Array.
 * @param {Crypto} cryptoAPI The crypto API to use. See getCrypto() for details.
 * @returns {Promise<Uint8Array>} The decrypted padded message.
 */
export async function decryptPaddedUnchecked(
  ciphertextBytes: Uint8Array | string,
  recipientSkBytes: Uint8Array | string,
  cryptoAPI?: Crypto
): Promise<Uint8Array> {
  const decrypted = await _decrypt(
    convertToBytes(ciphertextBytes),
    convertToBytes(recipientSkBytes),
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
  cryptoAPI?: Crypto
): Promise<Uint8Array> {
  if (!cryptoAPI) {
    cryptoAPI = await getCrypto();
  }
  const recipientPub = secp.Point.fromHex(recipientPk);
  const ephSk = secp.utils.randomPrivateKey();
  const ephPk = secp.getPublicKey(ephSk, true);

  const ephSkBigInt = BigInt(toHexString(ephSk, true));
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
  cryptoAPI?: Crypto
): Promise<Uint8Array> {
  if (!cryptoAPI) {
    cryptoAPI = await getCrypto();
  }
  if (ciphertextBytes.length < 45) {
    throw new Error(
      `Invalid ciphertext length ${ciphertextBytes.length} bytes, expected at least 45 bytes`
    );
  }
  const ephPk = secp.Point.fromHex(ciphertextBytes.slice(0, 33));
  const iv = ciphertextBytes.slice(33, 45);
  const ciphertext = ciphertextBytes.slice(45);

  const skBigInt = BigInt(toHexString(recipientSkBytes, true));
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

async function decodePadded(paddedMessage: Uint8Array): Promise<Uint8Array> {
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

  return paddedMessage.subarray(4, messageLength + 4);
}
