import * as x25519 from '@stablelib/x25519';
import { Bytes, DHAlgorithm, DHKeyPair, DHPrivateKey, DHPublicKey } from './types';
import * as proto from '../proto';

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
}