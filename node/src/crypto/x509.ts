import * as cc from 'commons-crypto';
import { hash } from '@stablelib/sha256';
import {
    Bytes,
    PublicAlgorithm,
    SignaturePrivateKey,
    SignaturePublicKey,
    PublicKey, PrivateKey,
} from './types';
import * as proto from '../proto';

export class X509Certificate implements PublicKey {
    constructor(
        public readonly key: cc.CertificateObject,
        public readonly raw: Bytes,
    ) {}

    // Key

    isDHKey(): boolean {
        return false;
    }

    isSignatureKey(): boolean {
        return true;
    }

    algorithm(): PublicAlgorithm {
        return x509SignatureAlgorithm;
    }

    // PublicKey

    marshalToProto(): proto.PublicKey {
        return proto.PublicKey.create({
            format: proto.KeyFormat.KeyFormatX509Certificate,
            data: this.key.export({
                type: 'spki',
                format: 'der',
            }),
        });
    }

    async verify(data: Bytes, signature: Bytes): Promise<boolean> {
        return this.key.verify('2.16.840.1.101.3.4.2.1', Buffer.from(hash(data)), Buffer.from(signature));
    }
}

export class X509Pkcs8PrivateKey implements SignaturePrivateKey {
    constructor(
        public readonly certificate: X509Certificate,
        public readonly key: cc.AsymmetricKeyObject,
    ) {}

    // Key

    isDHKey(): boolean {
        return false;
    }

    isSignatureKey(): boolean {
        return true;
    }

    algorithm(): PublicAlgorithm {
        return x509SignatureAlgorithm;
    }

    // SignaturePrivateKey

    getPublic(): PublicKey {
        return this.certificate;
    }

    getSignaturePublicKey(): SignaturePublicKey {
        return this.certificate;
    }

    async sign(data: Bytes): Promise<Bytes> {
        return this.key.sign('2.16.840.1.101.3.4.2.1', Buffer.from(hash(data)));
    }
}

export class X509SignatureAlgorithm implements PublicAlgorithm {
    getKeyFormat(): proto.KeyFormat {
        return proto.KeyFormat.KeyFormatX509Certificate;
    }

    async unmarshalPublicKey(input: Uint8Array): Promise<X509Certificate> {
        const cert = cc.createCertificate({
            type: 'x509',
            key: Buffer.from(input),
            format: 'der',
        });
        return new X509Certificate(cert, input);
    }
}

export const x509SignatureAlgorithm = new X509SignatureAlgorithm();
