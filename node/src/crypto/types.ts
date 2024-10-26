import * as proto from '../proto';

export type Bytes = Uint8Array;
export type Uint64 = bigint;

export interface Cipher {
    readonly type: proto.CipherAlgorithm;
    seal: (key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array) => Uint8Array;
    open: (key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array) => Uint8Array;
}

export interface SignatureAlgorithm {
    readonly type: proto.SignatureAlgorithm;
    unmarshalPublicKey(input: Bytes): SignaturePublicKey;
}

export interface SignaturePrivateKey {
    readonly algorithm: SignatureAlgorithm;
    sign: (data: Bytes) => Promise<Bytes>;
}

export interface SignaturePublicKey {
    readonly algorithm: SignatureAlgorithm;
    verify: (data: Bytes, signature: Bytes) => Promise<boolean>;
    marshalToProto: () => proto.SignaturePublicKey;
}

export type SignatureKeyPair = {
    private: SignaturePrivateKey;
    public: SignaturePublicKey;
}

export interface DHAlgorithm {
    readonly type: proto.DHAlgorithm;

    generate(): DHKeyPair;
    unmarshalPublicKey(input: Bytes): DHPublicKey;
    unmarshalPrivateKey(input: Bytes): DHPrivateKey;
}

export interface DHPublicKey {
    readonly algorithm: DHAlgorithm;
    marshal(): Bytes;
}

export interface DHPrivateKey {
    readonly algorithm: DHAlgorithm;
    dh(peerKey: DHPublicKey): Bytes;
}

export type DHKeyPair = {
    private: DHPrivateKey,
    public: DHPublicKey,
}