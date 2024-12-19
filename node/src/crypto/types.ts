import * as proto from '../proto';

export type Bytes = Uint8Array;
export type Uint64 = bigint;

export enum KeyUsage {
    DH = 1,
    Signature = 2
}

export interface CipherAlgorithm {
    getType(): proto.CipherAlgorithm;
    seal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Promise<Uint8Array>;
    open(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array): Promise<Uint8Array>;
}

export interface Key {
    isDHKey(): boolean;
    isSignatureKey(): boolean;
    algorithm(): PublicAlgorithm;
}

export interface PublicKey extends Key {
    marshalToProto(): proto.PublicKey;
}

export interface PrivateKey extends Key {
    getPublic(): PublicKey;
}

export interface PublicAlgorithm {
    getKeyFormat(): proto.KeyFormat;
    unmarshalPublicKey(input: Uint8Array): Promise<PublicKey>;
}

export interface SignaturePublicKey extends PublicKey {
    verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface SignaturePrivateKey extends Key {
    getPublic(): PublicKey;
    getSignaturePublicKey(): SignaturePublicKey;
    sign(data: Uint8Array): Promise<Uint8Array>;
}

export interface DHAlgorithm extends PublicAlgorithm {
    getType(): proto.DHAlgorithm;
    generate(): Promise<DHKeyPair>;
    unmarshalDHPublicKey(input: Uint8Array): Promise<DHPublicKey>;
}

export interface DHPublicKey extends PublicKey {
    getDHAlgorithm(): DHAlgorithm;
    getDHAlgorithmProto(): proto.DHAlgorithm;
    marshal(): Uint8Array;
}

export interface DHPrivateKey extends Key {
    getPublic(): PublicKey;
    getDHAlgorithm(): DHAlgorithm;
    getDHAlgorithmProto(): proto.DHAlgorithm;
    getDHPublic(): DHPublicKey;
    dh(peerKey: DHPublicKey): Promise<Uint8Array>;
}

export interface DHKeyPair {
    public: DHPublicKey;
    private: DHPrivateKey;
}