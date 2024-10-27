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

    public encryptWithAd(plaintext: Bytes, ad: Bytes): Bytes {
        const cs = this.cs!;
        const ciphertext = cs.cipher.seal(cs.key, cs.nonce.getBytes(), plaintext, ad);
        cs.nonce.increment();
        return ciphertext;
    }

    public encryptAndMixHash(plaintext: Bytes, mustSecret: boolean): Bytes {
        let ciphertext: Uint8Array;
        // if key mixed
        if (this.cs) {
            ciphertext = this.encryptWithAd(plaintext, this.h);
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
    public decryptWithAd(ciphertext: Bytes, ad: Bytes): Bytes {
        const cs = this.cs!;
        const plaintext = this.cs!.cipher.open(cs.key, cs.nonce.getBytes(), ciphertext, ad);
        cs.nonce.increment();
        return plaintext;
    }

    // throwable
    public mixHashAndDecrypt(ciphertext: Bytes): Bytes {
        if (this.cs) {
            const plaintext = this.decryptWithAd(ciphertext, this.h);
            this.mixHash(ciphertext);
            return plaintext;
        } else {
            this.mixHash(ciphertext);
            return ciphertext;
        }
    }
}