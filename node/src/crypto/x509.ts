import * as cc from 'commons-crypto';
import { hash } from '@stablelib/sha256';
import { Bytes, SignatureAlgorithm, SignatureKeyPair, SignaturePrivateKey, SignaturePublicKey } from './types';
import * as proto from '../proto';

export class X509Certificate implements SignaturePublicKey {
    public readonly algorithm: SignatureAlgorithm = new X509SignatureAlgorithm();

    constructor(
        public readonly key: cc.CertificateObject,
        public readonly raw: Bytes,
    ) {}

    marshalToProto(): proto.SignaturePublicKey {
        return {
            algorithm: proto.SignatureAlgorithm.SignatureX509,
            data: this.raw,
        };
    }

    async verify(data: Bytes, signature: Bytes): Promise<boolean> {
        return this.key.verify('2.16.840.1.101.3.4.2.1', Buffer.from(hash(data)), Buffer.from(signature));
    }
}

export class X509Pkcs8PrivateKey implements SignaturePrivateKey {
    public readonly algorithm: SignatureAlgorithm = new X509SignatureAlgorithm();

    constructor(public readonly key: cc.AsymmetricKeyObject) {}

    async sign(data: Bytes): Promise<Bytes> {
        return this.key.sign('2.16.840.1.101.3.4.2.1', Buffer.from(hash(data)));
    }
}

export class X509SignatureAlgorithm implements SignatureAlgorithm {
    public readonly type: proto.SignatureAlgorithm = proto.SignatureAlgorithm.SignatureX509;

    generate(): SignatureKeyPair {
        throw new Error('not supported');
    }

    unmarshalPublicKey(input: Bytes): SignaturePublicKey {
        const cert = cc.createCertificate({
            type: 'x509',
            key: Buffer.from(input),
            format: 'der',
        });
        return new X509Certificate(cert, input);
    }
}
