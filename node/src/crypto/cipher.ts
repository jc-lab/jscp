import * as proto from '../proto';
import { AES } from '@stablelib/aes';
import { GCM } from '@stablelib/gcm';

export interface Cipher {
    readonly type: proto.CipherAlgorithm;
    seal: (key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array) => Uint8Array;
    open: (key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array) => Uint8Array;
}

export class AesGcmCipher implements Cipher {
    public readonly type: proto.CipherAlgorithm = proto.CipherAlgorithm.CipherAesGcm;

    seal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
        const aead = new GCM(new AES(key, true));
        return aead.seal(nonce, plaintext, ad)!;
    }

    open(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array): Uint8Array {
        const aead = new GCM(new AES(key, false));
        const output = aead.open(nonce, ciphertext, ad);
        if (!output) {
            throw new Error('decrypt failed');
        }
        return output;
    }
}

export function getCipherAlgorithm(type: proto.CipherAlgorithm): Cipher {
    switch (type) {
        case proto.CipherAlgorithm.CipherAesGcm:
            return new AesGcmCipher();

        default:
            throw new Error(`unknown cipher algorithm: ${type}`);
    }
}