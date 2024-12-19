import * as hex from '@stablelib/hex';
import { AesGcmCipher } from './aes';

interface TestVector {
    description: string;
    key: string;
    nonce: string;
    plaintext: string;
    ad: string;
    ciphertext: string;
}

describe('AesGcmCipher', () => {
    const cipher = new AesGcmCipher();

    // Test vectors from the paper
    const testVectors: TestVector[] = [
        {
            description: 'Test Case 1: Empty plaintext and AD',
            key: '00000000000000000000000000000000',
            nonce: '000000000000000000000000',
            plaintext: '',
            ad: '',
            ciphertext: '58e2fccefa7e3061367f1d57a4e7455a'
        },
        {
            description: 'Test Case 2: Empty AD',
            key: '00000000000000000000000000000000',
            nonce: '000000000000000000000000',
            plaintext: '00000000000000000000000000000000',
            ad: '',
            ciphertext: '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf'
        },
        {
            description: 'Test Case 3: Basic with AD',
            key: 'feffe9928665731c6d6a8f9467308308',
            nonce: 'cafebabefacedbaddecaf888',
            plaintext: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
            ad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
            ciphertext: '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47'
        }
    ];

    describe('seal and open with test vectors', () => {
        testVectors.forEach((vector, index) => {
            it(`should correctly encrypt and decrypt ${vector.description}`, async () => {
                const key = hex.decode(vector.key);
                const nonce = hex.decode(vector.nonce);
                const plaintext = hex.decode(vector.plaintext);
                const ad = hex.decode(vector.ad);
                const expectedCiphertext = hex.decode(vector.ciphertext);

                // Test encryption
                const ciphertext = await cipher.seal(key, nonce, plaintext, ad);
                expect(ciphertext).toEqual(expectedCiphertext);

                // Test decryption
                const decrypted = await cipher.open(key, nonce, ciphertext, ad);
                expect(decrypted).toEqual(plaintext);
            });
        });
    });

    describe('error cases', () => {
        const validVector = testVectors[2]; // Using Test Case 3 as base for error tests

        it('should throw error when decrypting with wrong AD', async () => {
            const key = hex.decode(validVector.key);
            const nonce = hex.decode(validVector.nonce);
            const plaintext = hex.decode(validVector.plaintext);
            const ad = hex.decode(validVector.ad);
            const wrongAd = hex.decode('feedfacedeadbeeffeedfacedeadbeefabaddad3'); // Changed last byte

            const ciphertext = await cipher.seal(key, nonce, plaintext, ad);

            expect(cipher.open(key, nonce, ciphertext, wrongAd)).rejects.toThrow('decrypt failed');
        });

        it('should throw error when decrypting with wrong key', async () => {
            const key = hex.decode(validVector.key);
            const wrongKey = hex.decode(validVector.key.slice(0, -2) + 'ff'); // Change last byte of key
            const nonce = hex.decode(validVector.nonce);
            const plaintext = hex.decode(validVector.plaintext);
            const ad = hex.decode(validVector.ad);

            const ciphertext = await cipher.seal(key, nonce, plaintext, ad);

            expect(cipher.open(wrongKey, nonce, ciphertext, ad)).rejects.toThrow('decrypt failed');
        });

        it('should throw error when decrypting with wrong nonce', async () => {
            const key = hex.decode(validVector.key);
            const nonce = hex.decode(validVector.nonce);
            const wrongNonce = hex.decode(validVector.nonce.slice(0, -2) + 'ff'); // Change last byte of nonce
            const plaintext = hex.decode(validVector.plaintext);
            const ad = hex.decode(validVector.ad);

            const ciphertext = await cipher.seal(key, nonce, plaintext, ad);

            expect(cipher.open(key, wrongNonce, ciphertext, ad)).rejects.toThrow('decrypt failed');
        });
    });
});