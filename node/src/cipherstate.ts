import { Bytes, CipherAlgorithm, Nonce } from './crypto';

export class CipherState {
    public readonly nonce: Nonce;

    constructor(
        public readonly cipher: CipherAlgorithm,
        public readonly key: Bytes,
    ) {
        this.nonce = new Nonce(12);
    }
}
