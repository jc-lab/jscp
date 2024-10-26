import { Bytes, Cipher, Nonce } from './crypto';

export class CipherState {
    public readonly nonce: Nonce;

    constructor(
        public readonly cipher: Cipher,
        public readonly key: Bytes,
    ) {
        this.nonce = new Nonce(12);
    }
}
