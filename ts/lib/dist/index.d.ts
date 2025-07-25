export declare function toHex(buf: Uint8Array): string;
export declare function fromHex(hex: string): Uint8Array;
export declare function getCrypto(): Promise<Crypto>;
export type Keypair = {
    sk: Uint8Array;
    pk: Uint8Array;
};
export declare function generateKeypair(): Keypair;
export declare function encrypt(message: string, recipientPubHex: string, cryptoAPI: Crypto): Promise<string>;
export declare function decrypt(ciphertextHex: string, recipientSkHex: string, cryptoAPI: Crypto): Promise<string>;
export declare function encryptPadded(message: string, recipientPubHex: string, cryptoAPI: Crypto, paddedLength: number): Promise<string>;
export declare function decryptPadded(ciphertextHex: string, recipientSkHex: string, cryptoAPI: Crypto, paddedLength: number): Promise<string>;
export declare function decryptPaddedUnchecked(ciphertextHex: string, recipientSkHex: string, cryptoAPI: Crypto): Promise<string>;
