import * as x25519 from '@stablelib/x25519';
import { Bytes, DHAlgorithm, DHKeyPair, DHPrivateKey, DHPublicKey, PublicAlgorithm, PublicKey } from './types';
import * as proto from '../proto';

const symX25519PublicKey = Symbol.for('X25519PublicKey');

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
            public: new X25519PublicKey(keyPair.publicKey),
        };
    }

    async unmarshalDHPublicKey(input: Uint8Array): Promise<DHPublicKey> {
        return new X25519PublicKey(input);
    }
}

export class X25519PublicKey implements DHPublicKey {
    constructor(public readonly key: Uint8Array) {}

    get [symX25519PublicKey](): boolean {
        return true;
    }

    static checkInstance(obj: any): obj is X25519PublicKey {
        return obj[symX25519PublicKey] === true;
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
        return proto.PublicKey.create({
            format: proto.KeyFormat.KeyFormatX25519,
            data: this.key,
        });
    }

    // DHPublicKey

    getDHAlgorithm(): DHAlgorithm {
        return x25519Algorithm;
    }

    getDHAlgorithmProto(): proto.DHAlgorithm {
        return proto.DHAlgorithm.DHX25519;
    }

    marshal(): Bytes {
        return this.key;
    }
}

export class X25519PrivateKey implements DHPrivateKey {
    constructor(public readonly key: Uint8Array) {}

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

    getPublic(): PublicKey  {
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
        if (X25519PublicKey.checkInstance(peerKey)) {
            throw new Error(`invalid key type: ${peerKey?.algorithm()}`);
        }
        const peerKeyImpl = (peerKey as X25519PublicKey);
        return x25519.sharedKey(this.key, peerKeyImpl.key)
    }

    toPublic(): X25519PublicKey {
        const keyPair = x25519.generateKeyPairFromSeed(this.key);
        return new X25519PublicKey(keyPair.publicKey);
    }
}

const x25519Algorithm = new X25519Algorithm();
