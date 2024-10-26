import * as ed25519 from '@stablelib/ed25519';
import { Bytes, SignatureAlgorithm, SignatureKeyPair, SignaturePrivateKey, SignaturePublicKey } from './types';
import * as proto from '../proto';

export class Ed25519PrivateKey implements SignaturePrivateKey {
    public readonly algorithm: Ed25519Algorithm = new Ed25519Algorithm();

    constructor(
        private readonly key: Uint8Array,
    ) {
    }

    async sign(data: Bytes): Promise<Bytes> {
        return ed25519.sign(this.key, data);
    }

    marshal(): Bytes {
        return this.key;
    }
}

export class Ed25519PublicKey implements SignaturePublicKey {
    public readonly algorithm: Ed25519Algorithm = new Ed25519Algorithm();

    constructor(public readonly key: Uint8Array) {
    }

    async verify(data: Bytes, signature: Bytes): Promise<boolean> {
        return ed25519.verify(this.key, data, signature);
    }

    marshalToProto(): proto.SignaturePublicKey {
        return {
            algorithm: this.algorithm.type,
            data: this.key
        };
    }

    marshal(): Bytes {
        return this.key;
    }
}

export class Ed25519Algorithm implements SignatureAlgorithm {
    public readonly type: proto.SignatureAlgorithm = proto.SignatureAlgorithm.SignatureEd25519;

    generate(): SignatureKeyPair {
        const keyPair = ed25519.generateKeyPair();

        return {
            private: new Ed25519PrivateKey(keyPair.secretKey),
            public: new Ed25519PublicKey(keyPair.publicKey)
        };
    }

    unmarshalPublicKey(input: Bytes): SignaturePublicKey {
        return new Ed25519PublicKey(input);
    }
}