import { Bytes } from './types';
import * as proto from '../proto';

import * as x25519 from '@stablelib/x25519';

export type DHKeyPair = {
    private: DHPrivateKey,
    public: DHPublicKey,
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
    marshal(): Bytes;
}

export class X25519Algorithm implements DHAlgorithm {
    readonly type: proto.DHAlgorithm = proto.DHAlgorithm.DHX25519;

    generate(): DHKeyPair {
        const keyPair = x25519.generateKeyPair();

        return {
            private: new X25519PrivateKey(keyPair.secretKey),
            public: new X25519PublicKey(keyPair.publicKey),
        };
    }

    unmarshalPrivateKey(input: Bytes): DHPrivateKey {
        return new X25519PrivateKey(input);
    }

    unmarshalPublicKey(input: Bytes): DHPublicKey {
        return new X25519PublicKey(input);
    }
}

export class X25519PublicKey implements DHPublicKey {
    public readonly algorithm: X25519Algorithm = new X25519Algorithm();

    constructor(public readonly key: Uint8Array) {}

    marshal(): Bytes {
        return this.key;
    }
}

export class X25519PrivateKey implements DHPrivateKey {
    public readonly algorithm: X25519Algorithm = new X25519Algorithm();

    constructor(public readonly key: Uint8Array) {}

    dh(peerKey: DHPublicKey): Bytes {
        if (!(peerKey instanceof X25519PublicKey)) {
            throw new Error(`invalid key type: ${peerKey?.algorithm}`);
        }
        const peerKeyImpl = (peerKey as X25519PublicKey);
        return x25519.sharedKey(this.key, peerKeyImpl.key)
    }

    marshal(): Bytes {
        return this.key;
    }
}

export function getDHAlgorithm(type: proto.DHAlgorithm): DHAlgorithm {
    switch (type) {
        case proto.DHAlgorithm.DHX25519:
            return new X25519Algorithm();

        default:
            throw new Error(`unknown key type: ${type}`);
    }
}
