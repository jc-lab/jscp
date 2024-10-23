export interface Cipher {
    open: (key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array) => Uint8Array;
    seal: (key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array) => Uint8Array;
}
