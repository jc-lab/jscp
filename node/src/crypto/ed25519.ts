import * as ed25519 from '@stablelib/ed25519';
import {
    Bytes,
    PublicAlgorithm,
    PublicKey,
    SignaturePrivateKey,
    SignaturePublicKey
} from './types';
import * as proto from '../proto';
import { KeyFormat } from '../proto';

export class Ed25519PrivateKey implements SignaturePrivateKey {
    private readonly key: Uint8Array;

    constructor(
        key: Uint8Array,
    ) {
        switch (key.length) {
            case 32:
                const keyPair = ed25519.generateKeyPairFromSeed(key);
                this.key = keyPair.secretKey;
                break
            case 64:
                this.key = key;
                break
            default:
                throw new Error(`invalid key size: ${key.length}`);
        }
    }

    isDHKey(): boolean {
        return false;
    }

    isSignatureKey(): boolean {
        return true;
    }

    algorithm(): PublicAlgorithm {
        return ed25519Algorithm;
    }

    toPublic(): Ed25519PublicKey {
        return new Ed25519PublicKey(
            ed25519.extractPublicKeyFromSecretKey(this.key),
        )
    }

    getPublic(): PublicKey {
        return this.toPublic();
    }

    getSignaturePublicKey(): SignaturePublicKey {
        return this.toPublic();
    }

    async sign(data: Bytes): Promise<Bytes> {
        return ed25519.sign(this.key, data);
    }
}

export class Ed25519PublicKey implements SignaturePublicKey {
    constructor(public readonly key: Uint8Array) {
    }

    isDHKey(): boolean {
        return false;
    }

    isSignatureKey(): boolean {
        return true;
    }

    algorithm(): PublicAlgorithm {
        return ed25519Algorithm;
    }

    async verify(data: Bytes, signature: Bytes): Promise<boolean> {
        return ed25519.verify(this.key, data, signature);
    }

    marshalToProto(): proto.PublicKey {
        return {
            format: KeyFormat.KeyFormatEd25519,
            data: this.key,
        };
    }

    marshal(): Bytes {
        return this.key;
    }
}

export class Ed25519Algorithm implements PublicAlgorithm {
    getKeyFormat(): proto.KeyFormat {
        return proto.KeyFormat.KeyFormatEd25519;
    }

    async unmarshalPublicKey(input: Uint8Array): Promise<PublicKey> {
        return new Ed25519PublicKey(input);
    }

    generate(): {
        private: Ed25519PrivateKey,
        public: Ed25519PublicKey,
    } {
        const keyPair = ed25519.generateKeyPair();

        return {
            private: new Ed25519PrivateKey(keyPair.secretKey),
            public: new Ed25519PublicKey(keyPair.publicKey)
        };
    }
}

export const ed25519Algorithm = new Ed25519Algorithm();
