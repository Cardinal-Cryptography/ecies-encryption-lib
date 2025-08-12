import { strict as assert } from 'assert';
import { describe, it } from 'node:test';
import {
  generateKeypair,
  encrypt,
  decrypt,
  encryptPadded,
  decryptPadded,
  toHexString,
  fromHexString,
  getCrypto
} from '../ts/lib/src/index.js';

describe('Encryption and Decryption Tests', () => {
  const testMessage = 'Hello, World! This is a test message for encryption.';
  const testMessageBytes = new TextEncoder().encode(testMessage);
  const testMessageHex = toHexString(testMessageBytes);
  const paddedLength = 256; // Test with 256 bytes padding
  
  // Generate keypair for all tests
  const keypair = generateKeypair();

  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt with Uint8Array messageBytes', async () => {
      const crypto = await getCrypto();
      
      // Test with Uint8Array input
      const encrypted = await encrypt(testMessageBytes, keypair.pk, crypto);
      const decrypted = await decrypt(encrypted, keypair.sk, crypto);
      
      assert.ok(encrypted instanceof Uint8Array, 'Encrypted data should be Uint8Array');
      assert.ok(encrypted.length > 0, 'Encrypted data should not be empty');
      assert.notDeepEqual(encrypted, testMessageBytes, 'Encrypted data should be different from original');
      
      assert.ok(decrypted instanceof Uint8Array, 'Decrypted data should be Uint8Array');
      assert.deepEqual(decrypted, testMessageBytes, 'Decrypted data should match original');
      
      const decryptedText = new TextDecoder().decode(decrypted);
      assert.equal(decryptedText, testMessage, 'Decrypted text should match original message');
    });

    it('should encrypt and decrypt with hex string messageBytes', async () => {
      const crypto = await getCrypto();
      
      // Test with hex string input
      const encrypted = await encrypt(testMessageHex, keypair.pk, crypto);
      const decrypted = await decrypt(encrypted, keypair.sk, crypto);
      
      assert.ok(encrypted instanceof Uint8Array, 'Encrypted data should be Uint8Array');
      assert.ok(encrypted.length > 0, 'Encrypted data should not be empty');
      
      assert.ok(decrypted instanceof Uint8Array, 'Decrypted data should be Uint8Array');
      assert.deepEqual(decrypted, testMessageBytes, 'Decrypted data should match original bytes');
      
      const decryptedText = new TextDecoder().decode(decrypted);
      assert.equal(decryptedText, testMessage, 'Decrypted text should match original message');
    });

    it('should encrypt and decrypt with hex string public/private keys', async () => {
      const crypto = await getCrypto();
      const pkHex = toHexString(keypair.pk);
      const skHex = toHexString(keypair.sk);
      
      // Test with Uint8Array message and hex keys
      const encrypted = await encrypt(testMessageBytes, pkHex, crypto);
      const decrypted = await decrypt(encrypted, skHex, crypto);
      
      assert.deepEqual(decrypted, testMessageBytes, 'Decrypted data should match original');
      
      // Test with hex message and hex keys
      const encrypted2 = await encrypt(testMessageHex, pkHex, crypto);
      const decrypted2 = await decrypt(encrypted2, skHex, crypto);
      
      assert.deepEqual(decrypted2, testMessageBytes, 'Decrypted data should match original');
    });

    it('should produce different ciphertexts for the same message (randomness)', async () => {
      const crypto = await getCrypto();
      const encrypted1 = await encrypt(testMessageBytes, keypair.pk, crypto);
      const encrypted2 = await encrypt(testMessageBytes, keypair.pk, crypto);
      
      assert.notDeepEqual(encrypted1, encrypted2, 'Encryptions should be different due to randomness');
      
      const decrypted1 = await decrypt(encrypted1, keypair.sk, crypto);
      const decrypted2 = await decrypt(encrypted2, keypair.sk, crypto);
      
      assert.deepEqual(decrypted1, testMessageBytes, 'First decryption should match original');
      assert.deepEqual(decrypted2, testMessageBytes, 'Second decryption should match original');
    });

    it('should handle empty message', async () => {
      const crypto = await getCrypto();
      const emptyMessage = new Uint8Array(0);
      const emptyHex = '';
      
      // Test with empty Uint8Array
      const encrypted1 = await encrypt(emptyMessage, keypair.pk, crypto);
      const decrypted1 = await decrypt(encrypted1, keypair.sk, crypto);
      assert.deepEqual(decrypted1, emptyMessage, 'Empty Uint8Array should encrypt/decrypt correctly');
      
      // Test with empty hex string
      const encrypted2 = await encrypt(emptyHex, keypair.pk, crypto);
      const decrypted2 = await decrypt(encrypted2, keypair.sk, crypto);
      assert.deepEqual(decrypted2, emptyMessage, 'Empty hex string should encrypt/decrypt correctly');
    });

    it('should fail to decrypt with wrong private key', async () => {
      const crypto = await getCrypto();
      const wrongKeypair = generateKeypair();
      const encrypted = await encrypt(testMessageBytes, keypair.pk, crypto);
      
      await assert.rejects(
        async () => await decrypt(encrypted, wrongKeypair.sk, crypto),
        /OperationError|InvalidAccessError|Error/,
        'Decryption with wrong key should fail'
      );
    });
  });

  describe('encryptPadded and decryptPadded', () => {
    it('should encrypt and decrypt padded message with Uint8Array messageBytes', async () => {
      const crypto = await getCrypto();
      const encrypted = await encryptPadded(testMessageBytes, keypair.pk, paddedLength, crypto);
      const decrypted = await decryptPadded(encrypted, keypair.sk, paddedLength, crypto);
      
      assert.ok(encrypted instanceof Uint8Array, 'Encrypted data should be Uint8Array');
      assert.ok(encrypted.length > 0, 'Encrypted data should not be empty');
      
      assert.ok(decrypted instanceof Uint8Array, 'Decrypted data should be Uint8Array');
      assert.deepEqual(decrypted, testMessageBytes, 'Decrypted data should match original');
      
      const decryptedText = new TextDecoder().decode(decrypted);
      assert.equal(decryptedText, testMessage, 'Decrypted text should match original message');
    });

    it('should encrypt and decrypt padded message with hex string messageBytes', async () => {
      const crypto = await getCrypto();
      const encrypted = await encryptPadded(testMessageHex, keypair.pk, paddedLength, crypto);
      const decrypted = await decryptPadded(encrypted, keypair.sk, paddedLength, crypto);
      
      assert.ok(encrypted instanceof Uint8Array, 'Encrypted data should be Uint8Array');
      assert.ok(decrypted instanceof Uint8Array, 'Decrypted data should be Uint8Array');
      assert.deepEqual(decrypted, testMessageBytes, 'Decrypted data should match original bytes');
      
      const decryptedText = new TextDecoder().decode(decrypted);
      assert.equal(decryptedText, testMessage, 'Decrypted text should match original message');
    });

    it('should work with different padded lengths', async () => {
      const crypto = await getCrypto();
      const lengths = [64, 128, 512, 1024];
      
      for (const length of lengths) {
        const encrypted = await encryptPadded(testMessageBytes, keypair.pk, length, crypto);
        const decrypted = await decryptPadded(encrypted, keypair.sk, length, crypto);
        
        assert.deepEqual(decrypted, testMessageBytes, `Padding length ${length} should work correctly`);
      }
    });

    it('should handle minimum padded length (message length + 4)', async () => {
      const crypto = await getCrypto();
      const minLength = testMessageBytes.length + 4;
      
      const encrypted = await encryptPadded(testMessageBytes, keypair.pk, minLength, crypto);
      const decrypted = await decryptPadded(encrypted, keypair.sk, minLength, crypto);
      
      assert.deepEqual(decrypted, testMessageBytes, 'Minimum padding should work correctly');
    });

    it('should throw error for insufficient padded length', async () => {
      const crypto = await getCrypto();
      const insufficientLength = testMessageBytes.length + 3; // Less than required minimum
      
      await assert.rejects(
        async () => await encryptPadded(testMessageBytes, keypair.pk, insufficientLength, crypto),
        /Invalid padded length/,
        'Should throw error for insufficient padding length'
      );
    });

    it('should throw error when decrypting with wrong padded length', async () => {
      const crypto = await getCrypto();
      const encrypted = await encryptPadded(testMessageBytes, keypair.pk, paddedLength, crypto);
      const wrongLength = paddedLength + 50;
      
      await assert.rejects(
        async () => await decryptPadded(encrypted, keypair.sk, wrongLength, crypto),
        /Invalid padded length/,
        'Should throw error when padded length doesn\'t match'
      );
    });

    it('should produce different ciphertexts for the same padded message (randomness)', async () => {
      const crypto = await getCrypto();
      const encrypted1 = await encryptPadded(testMessageBytes, keypair.pk, paddedLength, crypto);
      const encrypted2 = await encryptPadded(testMessageBytes, keypair.pk, paddedLength, crypto);
      
      assert.notDeepEqual(encrypted1, encrypted2, 'Padded encryptions should be different due to randomness');
      
      const decrypted1 = await decryptPadded(encrypted1, keypair.sk, paddedLength, crypto);
      const decrypted2 = await decryptPadded(encrypted2, keypair.sk, paddedLength, crypto);
      
      assert.deepEqual(decrypted1, testMessageBytes, 'First padded decryption should match original');
      assert.deepEqual(decrypted2, testMessageBytes, 'Second padded decryption should match original');
    });

    it('should handle empty padded message', async () => {
      const crypto = await getCrypto();
      const emptyMessage = new Uint8Array(0);
      const emptyHex = '';
      const minPaddedLength = 4; // Minimum for empty message
      
      // Test with empty Uint8Array
      const encrypted1 = await encryptPadded(emptyMessage, keypair.pk, minPaddedLength, crypto);
      const decrypted1 = await decryptPadded(encrypted1, keypair.sk, minPaddedLength, crypto);
      assert.deepEqual(decrypted1, emptyMessage, 'Empty Uint8Array should encrypt/decrypt with padding correctly');
      
      // Test with empty hex string
      const encrypted2 = await encryptPadded(emptyHex, keypair.pk, minPaddedLength, crypto);
      const decrypted2 = await decryptPadded(encrypted2, keypair.sk, minPaddedLength, crypto);
      assert.deepEqual(decrypted2, emptyMessage, 'Empty hex string should encrypt/decrypt with padding correctly');
    });

    it('should fail to decrypt padded message with wrong private key', async () => {
      const crypto = await getCrypto();
      const wrongKeypair = generateKeypair();
      const encrypted = await encryptPadded(testMessageBytes, keypair.pk, paddedLength, crypto);
      
      await assert.rejects(
        async () => await decryptPadded(encrypted, wrongKeypair.sk, paddedLength, crypto),
        /OperationError|InvalidAccessError|Error/,
        'Padded decryption with wrong key should fail'
      );
    });
  });

  describe('Cross-compatibility tests', () => {
    it('should work with different input type combinations', async () => {
      const crypto = await getCrypto();
      const pkHex = toHexString(keypair.pk);
      const skHex = toHexString(keypair.sk);
      
      // All combinations for regular encrypt/decrypt
      const combinations = [
        { msg: testMessageBytes, pk: keypair.pk, sk: keypair.sk, desc: 'Uint8Array message, Uint8Array keys' },
        { msg: testMessageBytes, pk: pkHex, sk: skHex, desc: 'Uint8Array message, hex keys' },
        { msg: testMessageHex, pk: keypair.pk, sk: keypair.sk, desc: 'hex message, Uint8Array keys' },
        { msg: testMessageHex, pk: pkHex, sk: skHex, desc: 'hex message, hex keys' }
      ];
      
      for (const { msg, pk, sk, desc } of combinations) {
        const encrypted = await encrypt(msg, pk, crypto);
        const decrypted = await decrypt(encrypted, sk, crypto);
        assert.deepEqual(decrypted, testMessageBytes, `Regular encryption should work with: ${desc}`);
        
        // Also test padded versions
        const encryptedPadded = await encryptPadded(msg, pk, paddedLength, crypto);
        const decryptedPadded = await decryptPadded(encryptedPadded, sk, paddedLength, crypto);
        assert.deepEqual(decryptedPadded, testMessageBytes, `Padded encryption should work with: ${desc}`);
      }
    });
  });
});
