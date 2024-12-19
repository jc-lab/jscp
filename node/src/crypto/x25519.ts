import * as x25519 from '@stablelib/x25519';
import {
    PublicAlgorithm,
    DHAlgorithm,
    PublicKey,
    DHPublicKey,
    DHKeyPair,
    DHPrivateKey
} from './types';
import * as proto from '../proto';

export class X25519PrivateKey implements DHPrivateKey {
    constructor(
        private readonly key: Uint8Array,
    ) {
        if (key.length != x25519.SECRET_KEY_LENGTH) {
            throw new Error(`invalid key (size=${key.length})`);
        }
    }

    // Key

    isDHKey(): boolean {
        return true;
    }

    isSignatureKey(): boolean {
        return false;
    }

    algorithm(): PublicAlgorithm {
        return x25519Algorithm;
    }

    // DHPrivateKey

    getPublic(): PublicKey {
        return this.toPublic();
    }


    getDHAlgorithm(): DHAlgorithm {
        return x25519Algorithm;
    }

    getDHAlgorithmProto(): proto.DHAlgorithm {
        return proto.DHAlgorithm.DHX25519;
    }

    getDHPublic(): DHPublicKey {
        return this.toPublic();
    }

    async dh(peerKey: DHPublicKey): Promise<Uint8Array> {
        if (!(peerKey instanceof X25519PublicKey)) {
            throw new Error('peerKey is not X25519PublicKey');
        }
        return x25519.sharedKey(this.key, peerKey.key);
    }

    toPublic(): X25519PublicKey {
        return new X25519PublicKey(
            x25519.generateKeyPairFromSeed(this.key).publicKey
        )
    }
}

export class X25519PublicKey implements DHPublicKey {
    constructor(public readonly key: Uint8Array) {
        if (key.length != x25519.PUBLIC_KEY_LENGTH) {
            throw new Error(`invalid key (size=${key.length})`);
        }
    }

    // Key

    isDHKey(): boolean {
        return true;
    }

    isSignatureKey(): boolean {
        return false;
    }

    algorithm(): PublicAlgorithm {
        return x25519Algorithm;
    }

    // PublicKey

    marshalToProto(): proto.PublicKey {
        return {
            format: proto.KeyFormat.KeyFormatX25519,
            data: this.key,
        };
    }

    // DHPublicKey

    getDHAlgorithm(): DHAlgorithm {
        return x25519Algorithm;
    }

    getDHAlgorithmProto(): proto.DHAlgorithm {
        return proto.DHAlgorithm.DHX25519
    }

    marshal(): Uint8Array {
        return this.key;
    }
}

export class X25519Algorithm implements DHAlgorithm {
    // PublicAlgorithm
    getKeyFormat(): proto.KeyFormat {
        return proto.KeyFormat.KeyFormatX25519;
    }

    async unmarshalPublicKey(input: Uint8Array): Promise<PublicKey> {
        return new X25519PublicKey(input);
    }

    // DHAlgorithm

    getType(): proto.DHAlgorithm {
        return proto.DHAlgorithm.DHX25519;
    }

    async generate(): Promise<DHKeyPair> {
        const keyPair = x25519.generateKeyPair();

        return {
            private: new X25519PrivateKey(keyPair.secretKey),
            public: new X25519PublicKey(keyPair.publicKey)
        };
    }

    async unmarshalDHPublicKey(input: Uint8Array): Promise<DHPublicKey> {
        return new X25519PublicKey(input);
    }
}

export const x25519Algorithm = new X25519Algorithm();
