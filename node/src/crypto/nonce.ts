import { Bytes, Uint64 } from './types';

export class Nonce {
    private n: Uint64
    private readonly bytes: Bytes
    private readonly view: DataView

    constructor (size: number) {
        this.n = 0n
        this.bytes = new Uint8Array(size);
        this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
        this.view.setBigUint64(size - 8, this.n, true);
    }

    increment (): void {
        this.n++;
        // Even though we're treating the nonce as 8 bytes, RFC7539 specifies 12 bytes for a nonce.
        this.view.setBigUint64(this.bytes.length - 8, this.n, true);
    }

    getBytes (): Bytes {
        return this.bytes;
    }

    getUint64 (): Uint64 {
        return this.n;
    }
}