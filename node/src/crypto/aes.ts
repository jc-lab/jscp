import { AES } from '@stablelib/aes';
import { GCM } from '@stablelib/gcm';
import { CipherAlgorithm } from './types';
import * as proto from '../proto';

export class AesGcmCipher implements CipherAlgorithm {
    getType(): proto.CipherAlgorithm {
        return proto.CipherAlgorithm.CipherAesGcm;
    }

    async seal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
        const aead = new GCM(new AES(key, true));
        return aead.seal(nonce, plaintext, ad)!;
    }

    async open(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
        const aead = new GCM(new AES(key, false));
        const output = aead.open(nonce, ciphertext, ad);
        if (!output) {
            throw new Error('decrypt failed');
        }
        return output;
    }
}
