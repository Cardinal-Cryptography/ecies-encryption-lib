import * as secp from "@noble/secp256k1";

export type Keypair = { sk: Uint8Array; pk: Uint8Array };

export function generateKeypair(): Keypair {
  const sk = secp.utils.randomPrivateKey();
  const pk = secp.getPublicKey(sk, true);
  return { sk, pk };
}

export function fromHex(hex: Uint8Array | string): Uint8Array {
  return isBytes(hex)
    ? Uint8Array.from(hex as any)
    : secp.hexToBytes(removePrefix(hex as string));
}

export function toHex(uint8: Uint8Array, withPrefix: boolean = false): string {
  const hex = Array.from(uint8)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return withPrefix ? "0x" + hex : hex;
}

export async function getCrypto(): Promise<Crypto> {
  return typeof globalThis.crypto !== "undefined"
    ? globalThis.crypto
    : ((await import("node:crypto")).webcrypto as Crypto);
}

function isBytes(bytes: Uint8Array | string): boolean {
  return (
    bytes instanceof Uint8Array ||
    (ArrayBuffer.isView(bytes) && bytes.constructor.name === "Uint8Array")
  );
}

function removePrefix(hex: string): string {
  return hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
}
