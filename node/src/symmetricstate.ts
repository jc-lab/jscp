import { hash } from '@stablelib/sha256';
import { concat } from 'uint8arrays/concat';
import { Bytes, Cipher, hkdf } from './crypto';
import { CipherState } from './cipherstate';

const EMPTY = new Uint8Array(0);

export class SymmetricState {
    public ck: Bytes = EMPTY;
    public h: Bytes = EMPTY;
    public cs: CipherState | null = null;

    public mixHash(data: Bytes) {
        this.h = hash(concat([this.h, data]));
    }

    public mixKey(cipher: Cipher, key: Bytes) {
        const [ck, temp] = hkdf(key, this.ck);
        this.ck = ck;
        this.cs = new CipherState(cipher, temp);
    }

    public encryptAndMixHash(plaintext: Bytes, mustSecret: boolean): Bytes {
        let ciphertext: Uint8Array;
        // if key mixed
        if (this.cs) {
            ciphertext = this.cs.cipher.seal(this.cs.key, this.cs.nonce.getBytes(), plaintext, this.h);
            this.cs.nonce.increment();
        } else {
            if (mustSecret) {
                throw new Error('must secret');
            }
            ciphertext = plaintext;
        }
        this.mixHash(ciphertext);
        return ciphertext;
    }

    // throwable
    public mixHashAndDecrypt(ciphertext: Bytes): Bytes {
        if (this.cs) {
            const plaintext = this.cs.cipher.open(this.cs.key, this.cs.nonce.getBytes(), ciphertext, this.h);
            this.mixHash(ciphertext);
            this.cs.nonce.increment();
            return plaintext;
        } else {
            this.mixHash(ciphertext);
            return ciphertext;
        }
    }
}