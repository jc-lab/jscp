import { hash } from '@stablelib/sha256';
import { concat } from 'uint8arrays/concat';
import { CipherAlgorithm, Bytes, hkdf } from './crypto';
import { CipherState } from './cipherstate';

const EMPTY = new Uint8Array(0);

export class SymmetricState {
    public ck: Bytes = EMPTY;
    public h: Bytes = EMPTY;
    public cs: CipherState | null = null;

    public mixHash(data: Bytes) {
        this.h = hash(concat([this.h, data]));
    }

    public mixKey(cipher: CipherAlgorithm, key: Bytes) {
        const [ck, temp] = hkdf(key, this.ck);
        this.ck = ck;
        this.cs = new CipherState(cipher, temp);
    }

    public async encryptWithAd(plaintext: Bytes, ad: Bytes): Promise<Bytes> {
        const cs = this.cs!;
        const ciphertext = await cs.cipher.seal(cs.key, cs.nonce.getBytes(), plaintext, ad);
        cs.nonce.increment();
        return ciphertext;
    }

    public async encryptAndMixHash(plaintext: Bytes, mustSecret: boolean): Promise<Bytes> {
        let ciphertext: Uint8Array;
        // if key mixed
        if (this.cs) {
            ciphertext = await this.encryptWithAd(plaintext, this.h);
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
    public async decryptWithAd(ciphertext: Bytes, ad: Bytes): Promise<Bytes> {
        const cs = this.cs!;
        const plaintext = await this.cs!.cipher.open(cs.key, cs.nonce.getBytes(), ciphertext, ad);
        cs.nonce.increment();
        return plaintext;
    }

    // throwable
    public async mixHashAndDecrypt(ciphertext: Bytes): Promise<Bytes> {
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